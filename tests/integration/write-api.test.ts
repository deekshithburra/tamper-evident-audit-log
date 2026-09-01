import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEYS, buildTestApp, client, sampleEvent } from '../helpers.js';
import type { Application } from '../../src/app.js';

describe('POST /audit/events (Scenario A: write)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
  });
  afterEach(() => application.close());

  it('accepts a well-formed event and returns the sealed record', async () => {
    const response = await api.write(sampleEvent());

    expect(response.status).toBe(201);
    expect(response.body).toMatchObject({
      seq: 1,
      eventType: 'RECORD_UPDATED',
      actorId: 'user-1',
      resourceType: 'client_account',
      resourceId: 'acct-1000',
      lifecycleState: 'active',
      alg: 'sha256',
    });
    expect(response.body.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.body.recordHash).toMatch(/^[0-9a-f]{64}$/);
    expect(response.body.prevHash).toBe('0'.repeat(64));
  });

  it('links each record to its predecessor, forming a chain', async () => {
    const first = await api.write(sampleEvent());
    const second = await api.write(sampleEvent());
    const third = await api.write(sampleEvent());

    expect(second.body.prevHash).toBe(first.body.recordHash);
    expect(third.body.prevHash).toBe(second.body.recordHash);
    expect(third.body.seq).toBe(3);
  });

  it('never exposes field salts, which would defeat the hiding commitments', async () => {
    const response = await api.write(sampleEvent());
    expect(response.body.salts).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toContain('salts');
  });

  it('assigns recordedAt itself and defaults occurredAt to it', async () => {
    const before = Date.now();
    const response = await api.write(sampleEvent());
    const after = Date.now();

    const recordedAt = Date.parse(response.body.recordedAt);
    expect(recordedAt).toBeGreaterThanOrEqual(before);
    expect(recordedAt).toBeLessThanOrEqual(after);
    expect(response.body.occurredAt).toBe(response.body.recordedAt);
  });

  it('accepts a caller-supplied occurredAt within the permitted clock skew', async () => {
    const timestamp = new Date(Date.now() - 60_000).toISOString();
    const response = await api.write(sampleEvent({ timestamp }));

    expect(response.status).toBe(201);
    expect(response.body.occurredAt).toBe(timestamp);
    // The server's own timestamp is unaffected by the caller's claim.
    expect(Date.parse(response.body.recordedAt)).toBeGreaterThan(Date.parse(timestamp));
  });

  it('refuses a backdated timestamp beyond the clock skew bound', async () => {
    const response = await api.write(
      sampleEvent({ timestamp: new Date(Date.now() - 86_400_000).toISOString() }),
    );

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(response.body.error.message).toMatch(/beyond the permitted clock skew/);
  });

  it('refuses a future timestamp beyond the clock skew bound', async () => {
    const response = await api.write(
      sampleEvent({ timestamp: new Date(Date.now() + 86_400_000).toISOString() }),
    );
    expect(response.status).toBe(400);
    expect(response.body.error.message).toMatch(/in the future/);
  });

  describe('validation at the boundary', () => {
    const cases: Array<[string, Record<string, unknown>, RegExp]> = [
      ['missing eventType', { eventType: undefined }, /eventType/],
      ['empty actorId', { actorId: '   ' }, /actorId/],
      ['payload that is an array', { payload: [1, 2] }, /payload/],
      ['payload that is a string', { payload: 'not-an-object' }, /payload/],
      ['unknown top-level field', { unexpected: true }, /unexpected/],
      ['malformed event type', { eventType: '9-starts-with-digit' }, /eventType/],
      ['invalid timestamp', { timestamp: 'not-a-date' }, /timestamp/],
    ];

    for (const [name, override, matcher] of cases) {
      it(`rejects ${name}`, async () => {
        const response = await api.write(sampleEvent(override));
        expect(response.status).toBe(400);
        expect(JSON.stringify(response.body)).toMatch(matcher);
      });
    }

    it('rejects a payload with a non-finite number rather than coercing it', async () => {
      // JSON cannot carry NaN, so this arrives as a raw body the parser rejects - either way
      // the write must not succeed, because a value that cannot be canonicalized cannot be
      // hashed reproducibly.
      const response = await api.raw
        .post('/audit/events')
        .set('X-API-Key', KEYS.writer)
        .set('Content-Type', 'application/json')
        .send('{"eventType":"X","actorId":"a","resourceType":"r","resourceId":"i","payload":{"v":NaN}}');
      expect(response.status).toBe(400);
    });

    it('rejects a payload with too many leaf fields', async () => {
      const payload = Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`k${i}`, i]));
      const response = await api.write(sampleEvent({ payload }));
      expect(response.status).toBe(400);
      expect(response.body.error.message).toMatch(/leaf fields/);
    });

    it('rejects an oversized body before doing any hashing work', async () => {
      const payload = { blob: 'x'.repeat(400_000) };
      const response = await api.write(sampleEvent({ payload }));
      expect(response.status).toBe(413);
    });
  });

  it('preserves payload structure exactly as submitted', async () => {
    const payload = {
      nested: { deep: { value: 42 } },
      list: [1, 'two', null, { three: true }],
      unicode: 'näïve — 日本語',
    };
    const written = await api.write(sampleEvent({ payload }));
    const read = await api.getOne(written.body.eventId);
    expect(read.body.payload).toEqual(payload);
  });
});
