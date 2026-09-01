import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEYS, buildTestApp, client, sampleEvent } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Requirement B3: sensitive payload fields must be erasable without breaking the hash chain.
 *
 * The central assertion in this file is `recordHash` being byte-identical before and after a
 * redaction. If that ever fails, the scheme in ADR-0003 is broken and no amount of the rest
 * matters.
 */
describe('structured redaction (Scenario B)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;
  let eventId: string;

  const sensitivePayload = {
    account: { number: '123456789', holder: 'A. Client', branch: 'SF-01' },
    ssn: '555-01-0001',
    amount: 4200,
    context: { channel: 'web', ip: '198.51.100.4' },
  };

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    const created = await api.write(sampleEvent({ payload: sensitivePayload }));
    eventId = created.body.eventId;
    // Records after the redaction target, so the chain has to survive downstream too.
    await api.write(sampleEvent());
    await api.write(sampleEvent());
  });
  afterEach(() => application.close());

  it('erases the value while leaving recordHash BYTE-IDENTICAL', async () => {
    const before = application.audit.getByEventId(eventId);

    const response = await api.redact(eventId, {
      paths: ['account.number', 'ssn'],
      reason: 'Data subject erasure request DSR-2026-118',
    });

    expect(response.status).toBe(200);
    const after = application.audit.getByEventId(eventId);

    expect(after.recordHash).toBe(before.recordHash);
    expect(after.payloadRoot).toBe(before.payloadRoot);
    expect(after.prevHash).toBe(before.prevHash);
    expect(after.leaves).toEqual(before.leaves);
  });

  it('destroys the salt along with the value, making the erasure irreversible', async () => {
    await api.redact(eventId, { paths: ['ssn'], reason: 'privacy request' });
    const after = application.audit.getByEventId(eventId);

    expect(after.salts.ssn).toBeUndefined();
    // Without the salt, the retained leaf digest cannot be brute-forced back to the value even
    // by us - which is the difference between erasure and a reversible obfuscation.
    expect(after.leaves.find((leaf) => leaf.path === 'ssn')).toBeDefined();
  });

  it('removes only the named fields, leaving the rest of the payload readable', async () => {
    await api.redact(eventId, { paths: ['account.number'], reason: 'privacy request' });
    const record = await api.getOne(eventId);

    expect(record.body.payload).toEqual({
      account: { holder: 'A. Client', branch: 'SF-01' },
      ssn: '555-01-0001',
      amount: 4200,
      context: { channel: 'web', ip: '198.51.100.4' },
    });
  });

  it('keeps the chain verifiable after redaction', async () => {
    await api.redact(eventId, { paths: ['ssn', 'account.number'], reason: 'privacy request' });

    const response = await api.verify();
    expect(response.status).toBe(200);
    expect(response.body.intact).toBe(true);
    expect(response.body.firstViolation).toBeNull();
  });

  it('records what was redacted, by whom and why - in the same chain', async () => {
    await api.redact(eventId, {
      paths: ['ssn'],
      reason: 'Data subject erasure request DSR-2026-118',
    });

    const record = await api.getOne(eventId);
    expect(record.body.redactions).toHaveLength(1);
    expect(record.body.redactions[0]).toMatchObject({
      path: 'ssn',
      reason: 'Data subject erasure request DSR-2026-118',
    });
    expect(record.body.redactions[0].redactedBy).toMatch(/^key:admin:/);

    const meta = await api.read('?eventType=PAYLOAD_REDACTED&limit=10');
    expect(meta.body.items).toHaveLength(1);
    expect(meta.body.items[0].payload).toMatchObject({
      targetEventId: eventId,
      paths: ['ssn'],
      reason: 'Data subject erasure request DSR-2026-118',
    });
  });

  it('handles repeated and overlapping redactions idempotently', async () => {
    await api.redact(eventId, { paths: ['ssn'], reason: 'first request' });
    const second = await api.redact(eventId, { paths: ['ssn', 'amount'], reason: 'second request' });

    expect(second.status).toBe(200);
    const record = application.audit.getByEventId(eventId);
    expect(record.redactions.map((r) => r.path).sort()).toEqual(['amount', 'ssn']);
    expect(record.payload).not.toHaveProperty('ssn');
    expect(record.payload).not.toHaveProperty('amount');

    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
  });

  it('redacts an array element without shifting its siblings', async () => {
    // Splicing the array would renumber every later element, changing their leaf paths - which
    // the verifier would correctly read as tampering. The element is nulled instead.
    const created = await api.write(
      sampleEvent({ payload: { items: ['keep-a', 'REMOVE', 'keep-b'] } }),
    );
    await api.redact(created.body.eventId, { paths: ['items.1'], reason: 'privacy request' });

    const record = await api.getOne(created.body.eventId);
    expect(record.body.payload.items).toEqual(['keep-a', null, 'keep-b']);

    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
  });

  it('rejects a path that does not exist in the record, and says which are valid', async () => {
    const response = await api.redact(eventId, {
      paths: ['account.nonexistent'],
      reason: 'privacy request',
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).toMatch(/Unknown payload path/);
    expect(response.body.error.message).toMatch(/account\.number/);
  });

  it('requires a reason, because the reason is recorded permanently', async () => {
    const response = await api.redact(eventId, { paths: ['ssn'], reason: 'x' });
    expect(response.status).toBe(400);
  });

  it('refuses to redact an archived record, whose payload is already gone', async () => {
    await api.retention({ windowDays: 0 });
    const response = await api.redact(eventId, { paths: ['ssn'], reason: 'privacy request' });
    expect(response.status).toBe(409);
    expect(response.body.error.message).toMatch(/already been destroyed/);
  });

  it('is admin-only: neither a writer nor an auditor can erase evidence', async () => {
    for (const key of [KEYS.writer, KEYS.reader, KEYS.auditor]) {
      const response = await api.redact(eventId, { paths: ['ssn'], reason: 'privacy request' }, key);
      expect(response.status).toBe(403);
    }
  });

  it('still detects a payload edit disguised as a redaction', async () => {
    // The attack: use the legitimate redaction column to *change* a value rather than remove
    // it. The salt is still present, so the leaf re-derives to something different and the
    // root no longer matches.
    const db = application.repo.unsafeRawHandle();
    const record = application.audit.getByEventId(eventId);
    db.prepare('UPDATE audit_events SET payload_json = ? WHERE seq = ?').run(
      JSON.stringify({ ...sensitivePayload, amount: 999_999 }),
      record.seq,
    );

    const response = await api.verify();
    expect(response.body.intact).toBe(false);
    expect(response.body.firstViolation.type).toBe('PAYLOAD_ROOT_MISMATCH');
    expect(response.body.firstViolation.paths).toContain('amount');
  });
});
