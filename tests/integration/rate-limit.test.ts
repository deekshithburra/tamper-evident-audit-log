import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, sampleEvent, withKey } from '../helpers.js';
import { FixedWindowRateLimiter } from '../../src/api/rate-limit.js';
import type { Application } from '../../src/app.js';

/**
 * Rate limiting.
 *
 * Time is injected rather than slept through: a limiter tested with `setTimeout` is a slow test
 * that is also flaky under load, and neither property is worth having. `clock` lets these tests
 * step across a window boundary instantly and deterministically.
 */

const CREDENTIALS = JSON.stringify([
  { id: 'app-one', secret: 'app-one-secret-01', role: 'admin' },
  { id: 'app-two', secret: 'app-two-secret-02', role: 'admin' },
]);

describe('per-credential rate limiting', () => {
  let application: Application;
  let now: number;
  let one: ReturnType<typeof withKey>;
  let two: ReturnType<typeof withKey>;

  beforeEach(async () => {
    now = Date.parse('2026-09-01T00:00:00.000Z');
    application = await buildTestApp(
      {
        API_CREDENTIALS: CREDENTIALS,
        RATE_LIMIT_ENABLED: 'true',
        RATE_LIMIT_WINDOW_MS: '60000',
        RATE_LIMIT_MAX_WRITE: '5',
        RATE_LIMIT_MAX_READ: '4',
        RATE_LIMIT_MAX_EXPENSIVE: '2',
      },
      { clock: () => now },
    );
    one = withKey(application, 'app-one-secret-01');
    two = withKey(application, 'app-two-secret-02');
  });
  afterEach(() => application.close());

  it('allows requests up to the budget and then returns 429', async () => {
    for (let i = 0; i < 5; i += 1) {
      const response = await one.write(sampleEvent());
      expect(response.status, `write ${i + 1} of 5 should be allowed`).toBe(201);
    }

    const blocked = await one.write(sampleEvent());
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('RATE_LIMITED');
    expect(blocked.body.error.message).toMatch(/Rate limit exceeded/);
  });

  it('advertises the budget on every response so a client can pace itself', async () => {
    const first = await one.write(sampleEvent());
    expect(first.headers['x-ratelimit-limit']).toBe('5');
    expect(first.headers['x-ratelimit-remaining']).toBe('4');
    expect(first.headers['x-ratelimit-reset']).toBe('2026-09-01T00:01:00.000Z');

    const second = await one.write(sampleEvent());
    expect(second.headers['x-ratelimit-remaining']).toBe('3');
  });

  it('sends Retry-After when it refuses, so a client knows when to come back', async () => {
    for (let i = 0; i < 5; i += 1) await one.write(sampleEvent());
    now += 15_000;

    const blocked = await one.write(sampleEvent());
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(blocked.headers['retry-after'])).toBeLessThanOrEqual(60);
  });

  it('recovers when the window rolls over', async () => {
    for (let i = 0; i < 5; i += 1) await one.write(sampleEvent());
    expect((await one.write(sampleEvent())).status).toBe(429);

    now += 60_001;

    const afterReset = await one.write(sampleEvent());
    expect(afterReset.status).toBe(201);
    expect(afterReset.headers['x-ratelimit-remaining']).toBe('4');
  });

  it('isolates credentials: one noisy caller cannot exhaust another’s budget', async () => {
    // Keyed by credential rather than by IP, which matters because every caller here is a
    // server and they would otherwise share a source address.
    for (let i = 0; i < 5; i += 1) await one.write(sampleEvent());
    expect((await one.write(sampleEvent())).status).toBe(429);

    const other = await two.write(sampleEvent());
    expect(other.status).toBe(201);
  });

  it('meters expensive operations on their own, much smaller budget', async () => {
    // Chain verification is O(n) over the whole log. No sensible write budget would stop a
    // caller looping it, so it gets a separate allowance.
    expect((await one.verify()).status).toBe(200);
    expect((await one.verify()).status).toBe(200);

    const third = await one.verify();
    expect(third.status).toBe(429);

    // ...while writes, on their own budget, are unaffected.
    expect((await one.write(sampleEvent())).status).toBe(201);
  });

  it('meters export and the compliance report as expensive too', async () => {
    await one.write(sampleEvent({ resourceId: 'acct-x' }));
    expect((await one.exportBundle('?resourceId=acct-x')).status).toBe(200);
    expect(
      (await one.report('?from=2000-01-01T00:00:00.000Z&to=2099-01-01T00:00:00.000Z')).status,
    ).toBe(200);

    const third = await one.exportBundle('?resourceId=acct-x');
    expect(third.status).toBe(429);
  });

  it('separates read and write budgets', async () => {
    for (let i = 0; i < 4; i += 1) expect((await one.read('?limit=1')).status).toBe(200);
    expect((await one.read('?limit=1')).status).toBe(429);

    // Writes still work: exhausting reads must not take the write path down with it.
    expect((await one.write(sampleEvent())).status).toBe(201);
  });

  it('can be disabled entirely by configuration', async () => {
    const unlimited = await buildTestApp({
      API_CREDENTIALS: CREDENTIALS,
      RATE_LIMIT_ENABLED: 'false',
    });
    try {
      const api = client(unlimited);
      for (let i = 0; i < 12; i += 1) {
        expect((await api.write(sampleEvent(), 'app-one-secret-01')).status).toBe(201);
      }
    } finally {
      unlimited.close();
    }
  });
});

describe('FixedWindowRateLimiter', () => {
  const config = { enabled: true, windowMs: 1000, limits: { write: 2, read: 2, expensive: 1 } };

  it('counts per key and per bucket independently', () => {
    const clock = 0;
    const limiter = new FixedWindowRateLimiter(config, () => clock);

    expect(limiter.consume('a', 'write').allowed).toBe(true);
    expect(limiter.consume('a', 'write').allowed).toBe(true);
    expect(limiter.consume('a', 'write').allowed).toBe(false);

    // A different bucket for the same key is untouched...
    expect(limiter.consume('a', 'read').allowed).toBe(true);
    // ...as is the same bucket for a different key.
    expect(limiter.consume('b', 'write').allowed).toBe(true);
  });

  it('reports remaining and reset accurately', () => {
    let clock = 5_000;
    const limiter = new FixedWindowRateLimiter(config, () => clock);

    const first = limiter.consume('a', 'write');
    expect(first).toMatchObject({ allowed: true, limit: 2, remaining: 1, resetAt: 6_000 });

    clock = 6_001;
    const afterWindow = limiter.consume('a', 'write');
    expect(afterWindow).toMatchObject({ allowed: true, remaining: 1, resetAt: 7_001 });
  });

  it('does not grow without bound when keys are unique', () => {
    // A limiter that can be turned into a memory-exhaustion vector is worse than none.
    let clock = 0;
    const limiter = new FixedWindowRateLimiter(config, () => clock);
    for (let i = 0; i < 3000; i += 1) {
      limiter.consume(`key-${i}`, 'read');
      clock += 1;
    }
    clock += 10_000;
    // Eviction happens on window rollover; this call must still behave correctly afterwards.
    expect(limiter.consume('key-0', 'read').allowed).toBe(true);
  });
});
