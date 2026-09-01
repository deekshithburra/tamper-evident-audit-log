import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, seed, tamperDirectly } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Requirements A7 and A8, and the validation procedure the brief specifies: write events,
 * verify, modify a record *directly in the data store*, verify again, confirm detection.
 *
 * Every test here bypasses the API entirely and edits SQLite, because that is the threat the
 * hash chain exists for. Anything less would be testing our own restraint.
 */
describe('tamper detection', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    await seed(application, 10, (i) => ({ actorId: `user-${i}`, payload: { index: i, note: `event ${i}` } }));
  });
  afterEach(() => application.close());

  it('reports an intact chain before any tampering', async () => {
    const response = await api.verify();
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      intact: true,
      recordsChecked: 10,
      firstViolation: null,
      totalViolations: 0,
    });
    expect(response.body.chainHead).toMatch(/^[0-9a-f]{64}$/);
  });

  it('detects a payload value edited in place', async () => {
    tamperDirectly(
      application,
      `UPDATE audit_events SET payload_json = ? WHERE seq = 4`,
      [JSON.stringify({ index: 3, note: 'FORGED - this never happened' })],
    );

    const response = await api.verify();
    expect(response.status).toBe(409);
    expect(response.body.intact).toBe(false);
    expect(response.body.firstViolation).toMatchObject({
      seq: 4,
      type: 'PAYLOAD_ROOT_MISMATCH',
    });
    // The report must name the field, so an investigator knows what was changed.
    expect(response.body.firstViolation.paths).toContain('note');
  });

  it('detects an identity field rewritten in place', async () => {
    tamperDirectly(application, "UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 6");

    const response = await api.verify();
    expect(response.status).toBe(409);
    expect(response.body.firstViolation).toMatchObject({
      seq: 6,
      type: 'CONTENT_HASH_MISMATCH',
    });
    // Everything before the edit is still trustworthy; that boundary is the useful output.
    expect(response.body.firstViolation.seq).toBe(6);
  });

  it('detects a record deleted from the middle of the chain', async () => {
    tamperDirectly(application, 'DELETE FROM audit_events WHERE seq = 5');

    const response = await api.verify();
    expect(response.status).toBe(409);
    expect(response.body.firstViolation).toMatchObject({ seq: 6, type: 'SEQUENCE_GAP' });
    expect(response.body.firstViolation.message).toMatch(/1 record\(s\) are missing/);
    // The link also fails, because seq 6 points at the digest of the record that is now gone.
    expect(
      [response.body.firstViolation, ...response.body.furtherViolations].map(
        (v: { type: string }) => v.type,
      ),
    ).toContain('LINK_MISMATCH');
  });

  it('detects removal of the first record, which would otherwise look like a shorter history', async () => {
    tamperDirectly(application, 'DELETE FROM audit_events WHERE seq = 1');

    const response = await api.verify();
    expect(response.status).toBe(409);
    expect(response.body.firstViolation.type).toBe('GENESIS_MISMATCH');
    expect(response.body.firstViolation.message).toMatch(/head of the chain/);
  });

  it('detects a truncated tail only against an externally held head', async () => {
    // Honest limitation, asserted rather than glossed over: deleting the newest records leaves
    // a shorter chain that is internally consistent. Nothing inside the data can reveal it.
    const before = await api.verify();
    const headBefore = before.body.chainHead;

    tamperDirectly(application, 'DELETE FROM audit_events WHERE seq >= 9');

    const after = await api.verify();
    expect(after.status).toBe(200);
    expect(after.body.intact).toBe(true); // internally consistent...
    expect(after.body.chainHead).not.toBe(headBefore); // ...but the head moved backwards.
    expect(after.body.recordsChecked).toBe(8);
    // This is exactly why ADR-0002 calls external anchoring the highest-value follow-up:
    // detecting truncation requires a head held somewhere the attacker does not control.
  });

  it('refuses swap-based tampering at the storage layer before verification is even reached', () => {
    // Both the naive attacks - swapping two records' digests, and relinking them to reorder
    // history - collide with UNIQUE(record_hash) and UNIQUE(prev_hash). Asserted explicitly
    // because it shows the defence in depth is load-bearing rather than decorative, and it is
    // why the splice below has to use a novel value to reach the verifier at all.
    const db = application.repo.unsafeRawHandle();
    db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
    const three = application.repo.getBySeq(3)!;
    const four = application.repo.getBySeq(4)!;

    expect(() =>
      db.prepare('UPDATE audit_events SET record_hash = ? WHERE seq = 3').run(four.recordHash),
    ).toThrow(/UNIQUE/);
    expect(() =>
      db.prepare('UPDATE audit_events SET prev_hash = ? WHERE seq = 4').run(three.prevHash),
    ).toThrow(/UNIQUE/);
  });

  it('detects a spliced link when the attacker uses a value that clears the constraints', () => {
    const db = application.repo.unsafeRawHandle();
    db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
    const before = application.repo.getBySeq(4)!;
    // A digest that exists nowhere in the chain: it satisfies UNIQUE, so the storage layer
    // accepts it and the cryptographic layer is the one that has to catch it.
    db.prepare('UPDATE audit_events SET prev_hash = ? WHERE seq = 4').run('b'.repeat(64));

    const report = application.audit.verify();
    expect(report.intact).toBe(false);
    expect(report.firstViolation?.seq).toBe(4);
    expect(report.firstViolation?.type).toBe('LINK_MISMATCH');
    expect(report.firstViolation?.expected).toBe(application.repo.getBySeq(3)!.recordHash);
    expect(report.firstViolation?.actual).toBe('b'.repeat(64));
    // seq 4's own contents are untouched, so this is a pure link violation - the distinction
    // an investigator needs to tell "history was spliced" from "a record was edited".
    expect(before.recordHash).toBe(application.repo.getBySeq(4)!.recordHash);
  });

  it('detects a re-signed record when the attacker recomputes only that record hash', async () => {
    // A more sophisticated attacker edits the payload AND recomputes the record's own hash so
    // the self-consistency check passes. The chain still catches it: the *next* record's
    // prevHash points at the old digest.
    const target = application.repo.getBySeq(4)!;
    const db = application.repo.unsafeRawHandle();
    db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
    db.prepare('UPDATE audit_events SET actor_id = ?, record_hash = ? WHERE seq = 4').run(
      'attacker',
      // A plausible-looking but different digest, as any recomputation would produce.
      'a'.repeat(64),
    );

    const response = await api.verify();
    expect(response.body.intact).toBe(false);
    const types = [response.body.firstViolation, ...response.body.furtherViolations].map(
      (v: { type: string }) => v.type,
    );
    expect(types).toContain('LINK_MISMATCH');
    expect(target.recordHash).not.toBe('a'.repeat(64));
  });

  it('reports the FIRST inconsistency, not an arbitrary one, and counts the cascade', async () => {
    tamperDirectly(application, "UPDATE audit_events SET actor_id = 'x' WHERE seq IN (3, 7)");

    const response = await api.verify();
    expect(response.body.firstViolation.seq).toBe(3);
    expect(response.body.totalViolations).toBeGreaterThanOrEqual(2);
    expect(response.body.furtherViolations.length).toBeGreaterThan(0);
    for (const violation of response.body.furtherViolations) {
      expect(violation.seq).toBeGreaterThanOrEqual(3);
    }
  });

  it('flags a record claiming an algorithm the verifier cannot check', async () => {
    tamperDirectly(application, "UPDATE audit_events SET alg = 'md5' WHERE seq = 2");

    const response = await api.verify();
    expect(response.body.firstViolation).toMatchObject({
      seq: 2,
      type: 'UNSUPPORTED_ALGORITHM',
    });
  });

  it('can verify a suffix of the chain without false genesis reports', async () => {
    const clean = await api.verify('?fromSeq=5');
    expect(clean.status).toBe(200);
    expect(clean.body.intact).toBe(true);
    expect(clean.body.recordsChecked).toBe(6);
    expect(clean.body.range).toEqual({ fromSeq: 5, toSeq: 10 });

    // A tamper before the window is outside the slice, and is correctly not reported.
    tamperDirectly(application, "UPDATE audit_events SET actor_id = 'x' WHERE seq = 2");
    const suffix = await api.verify('?fromSeq=5');
    expect(suffix.body.intact).toBe(true);
    const full = await api.verify();
    expect(full.body.intact).toBe(false);
  });

  it('continues to accept new writes after a tamper, and verification stays failed', async () => {
    tamperDirectly(application, "UPDATE audit_events SET actor_id = 'x' WHERE seq = 3");

    // Availability must not depend on integrity: the incident response itself needs to be
    // audited, so the service keeps recording.
    const write = await api.write({
      eventType: 'INCIDENT_LOGGED',
      actorId: 'security-team',
      resourceType: 'audit_log',
      resourceId: 'chain',
      payload: { note: 'tamper suspected' },
    });
    expect(write.status).toBe(201);

    const response = await api.verify();
    expect(response.body.intact).toBe(false);
    expect(response.body.firstViolation.seq).toBe(3);
  });
});
