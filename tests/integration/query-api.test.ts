import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, sampleEvent, seed } from '../helpers.js';
import type { Application } from '../../src/app.js';

describe('GET /audit/events (Scenario A: query)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    await seed(application, 24, (i) => ({
      actorId: `user-${i % 3}`,
      resourceType: i % 2 === 0 ? 'client_account' : 'client_profile',
      resourceId: `res-${i % 4}`,
      eventType: i % 5 === 0 ? 'USER_LOGIN' : 'RECORD_UPDATED',
    }));
  });
  afterEach(() => application.close());

  it('returns everything when unfiltered', async () => {
    const response = await api.read('?limit=100');
    expect(response.status).toBe(200);
    expect(response.body.items).toHaveLength(24);
    expect(response.body.nextCursor).toBeNull();
  });

  it('filters by each supported dimension', async () => {
    const byActor = await api.read('?actorId=user-1&limit=100');
    expect(byActor.body.items.every((r: { actorId: string }) => r.actorId === 'user-1')).toBe(true);
    expect(byActor.body.items).toHaveLength(8);

    const byType = await api.read('?eventType=USER_LOGIN&limit=100');
    expect(byType.body.items).toHaveLength(5);

    const byResource = await api.read('?resourceType=client_account&resourceId=res-0&limit=100');
    expect(
      byResource.body.items.every(
        (r: { resourceType: string; resourceId: string }) =>
          r.resourceType === 'client_account' && r.resourceId === 'res-0',
      ),
    ).toBe(true);
    expect(byResource.body.items.length).toBeGreaterThan(0);
  });

  it('combines filters conjunctively', async () => {
    const response = await api.read('?actorId=user-0&eventType=USER_LOGIN&limit=100');
    for (const record of response.body.items) {
      expect(record.actorId).toBe('user-0');
      expect(record.eventType).toBe('USER_LOGIN');
    }
  });

  it('filters by time range, inclusive of from and exclusive of to', async () => {
    const all = await api.read('?limit=100');
    const items = all.body.items as Array<{ recordedAt: string; eventId: string }>;
    const from = items[5]!.recordedAt;
    const to = items[15]!.recordedAt;

    const ranged = await api.read(`?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&limit=100`);
    const ids = (ranged.body.items as Array<{ eventId: string }>).map((r) => r.eventId);

    expect(ids).toContain(items[5]!.eventId);
    expect(ids).not.toContain(items[15]!.eventId);
  });

  it('rejects a time range whose bounds are inverted', async () => {
    const response = await api.read('?from=2026-02-01T00:00:00.000Z&to=2026-01-01T00:00:00.000Z');
    expect(response.status).toBe(400);
  });

  it('paginates completely and without duplication', async () => {
    const seen: number[] = [];
    let cursor: string | null = null;
    let pages = 0;

    do {
      const query: string = cursor === null ? '?limit=7' : `?limit=7&cursor=${cursor}`;
      const response = await api.read(query);
      expect(response.status).toBe(200);
      seen.push(...(response.body.items as Array<{ seq: number }>).map((r) => r.seq));
      cursor = response.body.nextCursor;
      pages += 1;
      expect(pages).toBeLessThan(20);
    } while (cursor !== null);

    expect(seen).toHaveLength(24);
    expect(new Set(seen).size).toBe(24);
    expect(seen).toEqual([...seen].sort((a, b) => a - b));
  });

  it('keeps pagination stable when writes land between pages', async () => {
    // The failure mode this guards against is OFFSET pagination: a concurrent insert shifts
    // every later row, so a page either skips or repeats records. A regulator reconciling a
    // complete history cannot tolerate either.
    const firstPage = await api.read('?limit=10');
    expect(firstPage.body.items).toHaveLength(10);

    await api.write(sampleEvent({ actorId: 'interloper' }));

    const secondPage = await api.read(`?limit=10&cursor=${firstPage.body.nextCursor}`);
    const firstIds = (firstPage.body.items as Array<{ seq: number }>).map((r) => r.seq);
    const secondIds = (secondPage.body.items as Array<{ seq: number }>).map((r) => r.seq);

    expect(firstIds.filter((seq) => secondIds.includes(seq))).toEqual([]);
    expect(Math.min(...secondIds)).toBe(Math.max(...firstIds) + 1);
  });

  it('caps page size so a caller cannot demand the whole log in one response', async () => {
    const response = await api.read('?limit=5000');
    expect(response.status).toBe(400);
  });

  it('rejects an unknown query parameter rather than silently ignoring it', async () => {
    // Silently ignoring `actorID` would return every record while the caller believed they
    // had filtered - the kind of quiet wrong answer that is worse than an error.
    const response = await api.read('?actorID=user-1');
    expect(response.status).toBe(400);
  });

  it('fetches a single record by eventId, and 404s for an unknown one', async () => {
    const all = await api.read('?limit=1');
    const eventId = all.body.items[0].eventId;

    const found = await api.getOne(eventId);
    expect(found.status).toBe(200);
    expect(found.body.eventId).toBe(eventId);

    const missing = await api.getOne('11111111-2222-3333-4444-555555555555');
    expect(missing.status).toBe(404);
    expect(missing.body.error.code).toBe('NOT_FOUND');
  });
});
