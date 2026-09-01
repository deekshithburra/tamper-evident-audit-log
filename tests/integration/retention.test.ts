import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, seed } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Requirements B1 and B2.
 *
 * B2 is the one that matters: "the chain verification endpoint must handle the presence of
 * archived records correctly and not report a false positive break". The design meets it
 * structurally rather than by teaching the verifier an exception (ADR-0004), and the test that
 * proves it is the plain one - archive a lot of records, then verify with no special flags.
 */
describe('retention and archival (Scenario B)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    await seed(application, 20, (i) => ({
      resourceId: `acct-${i}`,
      payload: { index: i, secret: `value-${i}`, nested: { detail: `d-${i}` } },
    }));
  });
  afterEach(() => application.close());

  it('archives records older than the configured window', async () => {
    // windowDays: 0 makes every already-written record eligible.
    const response = await api.retention({ windowDays: 0 });
    expect(response.status).toBe(200);
    expect(response.body.archivedCount).toBe(20);
    expect(response.body.cutoff).toMatch(/^\d{4}-/);
  });

  it('archives nothing when every record is inside the window', async () => {
    const response = await api.retention({ windowDays: 3650 });
    expect(response.body.archivedCount).toBe(0);
  });

  it('KEEPS THE CHAIN INTACT after archival (requirement B2)', async () => {
    const before = await api.verify();
    expect(before.body.intact).toBe(true);
    const headBefore = before.body.chainHead;

    await api.retention({ windowDays: 0 });

    const after = await api.verify();
    expect(after.status).toBe(200);
    expect(after.body.intact).toBe(true);
    expect(after.body.firstViolation).toBeNull();
    // The chain grew by exactly one record: the retention run audits itself.
    expect(after.body.recordsChecked).toBe(21);
    expect(after.body.chainHead).not.toBe(headBefore);
  });

  it('destroys payload content while preserving the entire hash skeleton', async () => {
    const before = application.repo.getBySeq(3)!;
    await api.retention({ windowDays: 0 });
    const after = application.repo.getBySeq(3)!;

    expect(after.payload).toBeNull();
    expect(after.salts).toEqual({});
    expect(after.lifecycleState).toBe('archived');
    expect(after.archivedAt).not.toBeNull();

    // Nothing the hash covers may move. This is the whole design in five assertions.
    expect(after.recordHash).toBe(before.recordHash);
    expect(after.prevHash).toBe(before.prevHash);
    expect(after.payloadRoot).toBe(before.payloadRoot);
    expect(after.leaves).toEqual(before.leaves);
    expect(after.recordedAt).toBe(before.recordedAt);
  });

  it('excludes archived records from queries by default, and includes them on request', async () => {
    await api.retention({ windowDays: 0 });

    const byDefault = await api.read('?limit=100&resourceType=client_account');
    expect(byDefault.body.items.every((r: { lifecycleState: string }) => r.lifecycleState === 'active')).toBe(true);

    const withArchived = await api.read('?limit=100&resourceType=client_account&includeArchived=true');
    expect(withArchived.body.items.length).toBeGreaterThan(byDefault.body.items.length);
    expect(
      withArchived.body.items.some((r: { lifecycleState: string }) => r.lifecycleState === 'archived'),
    ).toBe(true);
  });

  it('still returns an archived record by id, with the payload absent rather than faked', async () => {
    const all = await api.read('?limit=1');
    const eventId = all.body.items[0].eventId;
    await api.retention({ windowDays: 0 });

    const response = await api.getOne(eventId);
    expect(response.status).toBe(200);
    expect(response.body.payload).toBeNull();
    expect(response.body.lifecycleState).toBe('archived');
    // The record's existence, actor, resource and timing survive: an investigator can still
    // see that something happened, which is the point of archiving rather than deleting.
    expect(response.body.actorId).toBe('user-1');
    expect(response.body.recordHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('records the retention run in the chain it just modified', async () => {
    await api.retention({ windowDays: 0 });
    const events = await api.read('?eventType=RETENTION_POLICY_APPLIED&limit=10');

    expect(events.body.items).toHaveLength(1);
    expect(events.body.items[0].payload).toMatchObject({ archivedCount: 20, windowDays: 0 });
    expect(events.body.items[0].actorId).toMatch(/^key:admin:/);
  });

  it('is idempotent: a second run finds nothing left to archive', async () => {
    await api.retention({ windowDays: 0 });
    const second = await api.retention({ windowDays: 0 });
    // The only remaining candidate is the first run's own audit event.
    expect(second.body.archivedCount).toBeLessThanOrEqual(1);
    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
  });

  it('honours the batch limit so a retention run cannot lock the store indefinitely', async () => {
    const response = await api.retention({ windowDays: 0, limit: 5 });
    expect(response.body.archivedCount).toBe(5);
    expect(response.body.archivedSeqs).toEqual([1, 2, 3, 4, 5]);
  });

  it('still detects tampering with an archived record', async () => {
    // Archival must not become a laundering route: content is gone, but the skeleton is still
    // covered by the chain, so editing an archived record is caught exactly like any other.
    await api.retention({ windowDays: 0 });
    const db = application.repo.unsafeRawHandle();
    db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
    db.exec("UPDATE audit_events SET actor_id = 'attacker' WHERE seq = 4");

    const response = await api.verify();
    expect(response.body.intact).toBe(false);
    expect(response.body.firstViolation).toMatchObject({ seq: 4, type: 'CONTENT_HASH_MISMATCH' });
  });

  it('rejects a negative retention window', async () => {
    const response = await api.retention({ windowDays: -1 });
    expect(response.status).toBe(400);
  });
});
