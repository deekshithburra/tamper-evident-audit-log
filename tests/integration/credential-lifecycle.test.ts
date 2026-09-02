import { afterEach, describe, expect, it } from 'vitest';
import { buildTestApp, sampleEvent, withKey } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Credential lifecycle, enforced per request rather than at boot.
 *
 * The distinction matters: a key checked only at startup keeps working until the next deploy,
 * which can be months. Expiry, staging and revocation are all evaluated on every call.
 */

const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * 86_400_000).toISOString();

function credentials(entries: Array<Record<string, unknown>>): string {
  return JSON.stringify(entries);
}

describe('credential lifecycle over HTTP', () => {
  let application: Application | undefined;
  afterEach(() => {
    application?.close();
    application = undefined;
  });

  async function appWith(entries: Array<Record<string, unknown>>): Promise<Application> {
    application = await buildTestApp({ API_CREDENTIALS: credentials(entries) });
    return application;
  }

  it('accepts an active credential', async () => {
    const app = await appWith([
      { id: 'svc', secret: 'active-secret-01', role: 'writer', expiresAt: iso(30) },
    ]);
    const api = withKey(app, 'active-secret-01');
    expect((await api.write(sampleEvent())).status).toBe(201);
  });

  it('rejects an expired credential with a code a client can act on', async () => {
    const app = await appWith([
      { id: 'svc', secret: 'expired-secret-1', role: 'writer', expiresAt: iso(-1) },
    ]);
    const response = await withKey(app, 'expired-secret-1').write(sampleEvent());

    expect(response.status).toBe(401);
    // Distinct from UNAUTHENTICATED: "rotate your key" and "you were never allowed" are
    // different problems with different fixes, and a client should be able to tell them apart.
    expect(response.body.error.code).toBe('CREDENTIAL_EXPIRED');
    expect(response.body.error.message).toMatch(/expired/i);
  });

  it('rejects a revoked credential immediately, ahead of its expiry', async () => {
    const app = await appWith([
      {
        id: 'svc',
        secret: 'revoked-secret-1',
        role: 'writer',
        expiresAt: iso(90),
        revokedAt: iso(-0.5),
      },
    ]);
    const response = await withKey(app, 'revoked-secret-1').write(sampleEvent());
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('CREDENTIAL_REVOKED');
  });

  it('rejects a staged credential until its activation time', async () => {
    const app = await appWith([
      { id: 'svc', secret: 'staged-secret-01', role: 'writer', notBefore: iso(7) },
    ]);
    const response = await withKey(app, 'staged-secret-01').write(sampleEvent());
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('CREDENTIAL_NOT_YET_VALID');
  });

  it('supports zero-downtime rotation: both secrets work during the overlap', async () => {
    const app = await appWith([
      { id: 'svc-web', secret: 'outgoing-secret-1', role: 'writer', expiresAt: iso(7) },
      { id: 'svc-web', secret: 'incoming-secret-1', role: 'writer', expiresAt: iso(90) },
    ]);

    expect((await withKey(app, 'outgoing-secret-1').write(sampleEvent())).status).toBe(201);
    expect((await withKey(app, 'incoming-secret-1').write(sampleEvent())).status).toBe(201);
  });

  it('advertises expiry on every successful response', async () => {
    const expiresAt = iso(45);
    const app = await appWith([
      { id: 'svc', secret: 'advertised-secret', role: 'writer', expiresAt },
    ]);
    const response = await withKey(app, 'advertised-secret').write(sampleEvent());

    expect(response.headers['x-credential-expires-at']).toBe(expiresAt);
    // Far from expiry: no nagging.
    expect(response.headers['x-credential-rotation-due']).toBeUndefined();
  });

  it('warns before expiry so rotation can be automated rather than discovered as an outage', async () => {
    const app = await appWith([
      { id: 'svc', secret: 'expiring-secret-1', role: 'writer', expiresAt: iso(3) },
    ]);
    const response = await withKey(app, 'expiring-secret-1').write(sampleEvent());

    expect(response.status).toBe(201);
    expect(response.headers['x-credential-rotation-due']).toBe('true');
    expect(response.headers['warning']).toMatch(/rotate it/);
  });

  it('surfaces rotation pressure on the credential inventory', async () => {
    const app = await appWith([
      { id: 'ops', secret: 'operator-secret-1', role: 'admin', expiresAt: iso(200) },
      { id: 'lapsing', secret: 'lapsing-secret-1', role: 'writer', expiresAt: iso(2) },
      { id: 'dead', secret: 'dead-secret-0001', role: 'reader', revokedAt: iso(-5) },
      { id: 'future', secret: 'future-secret-01', role: 'reader', notBefore: iso(10) },
    ]);
    const response = await withKey(app, 'operator-secret-1').credentials();

    expect(response.status).toBe(200);
    expect(response.body.rotationDue).toEqual(['lapsing']);

    const byId = Object.fromEntries(
      (response.body.credentials as Array<{ id: string; state: string }>).map((c) => [c.id, c.state]),
    );
    expect(byId).toMatchObject({ ops: 'active', lapsing: 'active', dead: 'revoked', future: 'pending' });
    expect(response.body.policy).toMatchObject({ rotationWarningDays: 14, maxLifetimeDays: 90 });
  });

  it('reports non-expiring credentials as such, and permits them only outside production', async () => {
    const app = await appWith([{ id: 'ops', secret: 'operator-secret-1', role: 'admin' }]);
    const response = await withKey(app, 'operator-secret-1').credentials();

    expect(response.body.credentials[0]).toMatchObject({ expiresAt: null, expiresInDays: null });
    expect(response.body.policy.nonExpiringPermitted).toBe(true);
  });

  it('keeps a lapsed credential out of every route, not just the write path', async () => {
    const app = await appWith([
      { id: 'svc', secret: 'lapsed-secret-01', role: 'admin', expiresAt: iso(-1) },
    ]);
    const api = withKey(app, 'lapsed-secret-01');

    for (const response of [
      await api.read(''),
      await api.verify(),
      await api.exportBundle('?resourceId=acct-1000'),
      await api.whoami(),
      await api.credentials(),
    ]) {
      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('CREDENTIAL_EXPIRED');
    }
  });
});
