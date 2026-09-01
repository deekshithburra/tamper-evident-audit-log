import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEYS, buildTestApp, client, sampleEvent } from '../helpers.js';
import type { Application } from '../../src/app.js';

describe('authentication and least-privilege authorization', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    await api.write(sampleEvent());
  });
  afterEach(() => application.close());

  it('rejects an unauthenticated request', async () => {
    const response = await api.raw.post('/audit/events').send(sampleEvent());
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });

  it('rejects an unrecognised key', async () => {
    const response = await api.write(sampleEvent(), 'not-a-real-key');
    expect(response.status).toBe(401);
  });

  it('accepts a key via either X-API-Key or a bearer token', async () => {
    const header = await api.raw
      .post('/audit/events')
      .set('Authorization', `Bearer ${KEYS.writer}`)
      .send(sampleEvent());
    expect(header.status).toBe(201);
  });

  it('leaves health unauthenticated, so a probe needs no credential', async () => {
    const response = await api.raw.get('/health');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
    // But it must not become an oracle: no record contents, only counts and the head digest.
    expect(JSON.stringify(response.body)).not.toMatch(/payload|actorId/);
  });

  describe('the role matrix', () => {
    // A compromised event producer is the most likely breach - it lives in every application -
    // so the writer role must not be able to read the history it contributes to.
    const matrix: Array<[string, string, Record<string, number>]> = [
      ['write', 'POST /audit/events', { writer: 201, reader: 403, auditor: 403, admin: 201 }],
      ['read', 'GET /audit/events', { writer: 403, reader: 200, auditor: 200, admin: 200 }],
      ['verify', 'GET /audit/verify', { writer: 403, reader: 403, auditor: 200, admin: 200 }],
      ['export', 'GET /audit/export', { writer: 403, reader: 403, auditor: 200, admin: 200 }],
      ['redact', 'POST redactions', { writer: 403, reader: 403, auditor: 403, admin: 200 }],
      ['retention', 'POST retention', { writer: 403, reader: 403, auditor: 403, admin: 200 }],
    ];

    for (const [operation, label, expectations] of matrix) {
      for (const [role, status] of Object.entries(expectations)) {
        it(`${label}: ${role} gets ${status}`, async () => {
          const key = KEYS[role as keyof typeof KEYS];
          const existing = (await api.read('?limit=1', KEYS.reader)).body.items[0];

          const response = await (async () => {
            switch (operation) {
              case 'write':
                return api.write(sampleEvent(), key);
              case 'read':
                return api.read('?limit=1', key);
              case 'verify':
                return api.verify('', key);
              case 'export':
                return api.exportBundle('?resourceId=acct-1000', key);
              case 'redact':
                return api.redact(
                  existing.eventId,
                  { paths: ['field'], reason: 'privacy request' },
                  key,
                );
              default:
                return api.retention({ windowDays: 3650 }, key);
            }
          })();

          expect(response.status).toBe(status);
        });
      }
    }
  });

  it('explains which capability was missing, without revealing what else exists', async () => {
    const response = await api.verify('', KEYS.writer);
    expect(response.status).toBe(403);
    expect(response.body.error.message).toMatch(/chain:verify/);
    expect(response.body.error.message).toMatch(/writer/);
  });

  it('never echoes a credential back in a response or an error', async () => {
    const bad = await api.write(sampleEvent(), 'super-secret-wrong-key');
    expect(JSON.stringify(bad.body)).not.toContain('super-secret-wrong-key');
  });

  it('sets conservative security headers on every response', async () => {
    const response = await api.read('?limit=1');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('DENY');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it('does not leak internals on an unhandled failure', async () => {
    const response = await api.raw.get('/nonexistent').set('X-API-Key', KEYS.reader);
    expect(response.status).toBe(404);
    expect(JSON.stringify(response.body)).not.toMatch(/at .*\.ts:|node_modules/);
  });
});
