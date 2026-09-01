import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, sampleEvent } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * The race in the write path (ADR-0005).
 *
 * Appending is a read-modify-write on shared state: read the tip, compute prevHash, insert.
 * Two writers that read the same tip fork the chain. These tests assert the invariant - one
 * predecessor per record, contiguous sequence, verifiable chain - rather than the mechanism,
 * so they stay honest if the storage engine is ever swapped for Postgres.
 */
describe('concurrent appends', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
  });
  afterEach(() => application.close());

  it('serializes 100 concurrent writes into one unforked chain', async () => {
    const responses = await Promise.all(
      Array.from({ length: 100 }, (_, i) =>
        api.write(sampleEvent({ actorId: `user-${i}`, payload: { i } })),
      ),
    );

    expect(responses.every((r) => r.status === 201)).toBe(true);

    const seqs = responses.map((r) => r.body.seq as number).sort((a, b) => a - b);
    expect(seqs).toEqual(Array.from({ length: 100 }, (_, i) => i + 1));

    // No two records may claim the same predecessor: that is what a fork looks like.
    const prevHashes = responses.map((r) => r.body.prevHash as string);
    expect(new Set(prevHashes).size).toBe(100);

    const recordHashes = responses.map((r) => r.body.recordHash as string);
    expect(new Set(recordHashes).size).toBe(100);

    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
    expect(verify.body.recordsChecked).toBe(100);
  });

  it('keeps the chain verifiable when reads, writes and verification interleave', async () => {
    await Promise.all([
      ...Array.from({ length: 30 }, () => api.write(sampleEvent())),
      ...Array.from({ length: 10 }, () => api.read('?limit=5')),
      ...Array.from({ length: 5 }, () => api.verify()),
    ]);

    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
    expect(verify.body.recordsChecked).toBe(30);
  });

  it('keeps redaction and appends consistent under interleaving', async () => {
    const seeded = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        api.write(sampleEvent({ payload: { secret: `s-${i}`, keep: i } })),
      ),
    );

    await Promise.all([
      ...seeded.map((r) =>
        api.redact(r.body.eventId, { paths: ['secret'], reason: 'bulk erasure request' }),
      ),
      ...Array.from({ length: 10 }, () => api.write(sampleEvent())),
    ]);

    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);

    for (const response of seeded) {
      const record = application.audit.getByEventId(response.body.eventId);
      expect(record.payload).not.toHaveProperty('secret');
      expect(record.recordHash).toBe(response.body.recordHash);
    }
  });
});
