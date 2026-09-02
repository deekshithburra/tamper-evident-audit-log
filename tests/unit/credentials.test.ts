import { describe, expect, it } from 'vitest';
import { CredentialStore, type Credential } from '../../src/api/credentials.js';
import { loadConfig } from '../../src/config.js';

const at = (iso: string) => new Date(iso);
const base: Credential = { id: 'svc-web', secret: 'secret-alpha-0001', role: 'reader' };

describe('credential lifecycle', () => {
  it('accepts an active credential and reports time remaining', () => {
    const store = new CredentialStore([{ ...base, expiresAt: '2026-10-01T00:00:00.000Z' }]);
    const result = store.authenticate('secret-alpha-0001', at('2026-09-01T00:00:00.000Z'));

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.credential.id).toBe('svc-web');
      expect(result.expiresInMs).toBe(30 * 86_400_000);
    }
  });

  it('rejects an expired credential with a distinct reason', () => {
    const store = new CredentialStore([{ ...base, expiresAt: '2026-08-01T00:00:00.000Z' }]);
    const result = store.authenticate('secret-alpha-0001', at('2026-09-01T00:00:00.000Z'));

    expect(result).toMatchObject({ ok: false, reason: 'EXPIRED', credentialId: 'svc-web' });
  });

  it('treats the expiry instant as exclusive', () => {
    const store = new CredentialStore([{ ...base, expiresAt: '2026-09-01T00:00:00.000Z' }]);
    expect(store.authenticate('secret-alpha-0001', at('2026-08-31T23:59:59.999Z')).ok).toBe(true);
    expect(store.authenticate('secret-alpha-0001', at('2026-09-01T00:00:00.000Z')).ok).toBe(false);
  });

  it('rejects a staged credential before its notBefore', () => {
    const store = new CredentialStore([{ ...base, notBefore: '2026-10-01T00:00:00.000Z' }]);
    expect(store.authenticate('secret-alpha-0001', at('2026-09-01T00:00:00.000Z'))).toMatchObject({
      ok: false,
      reason: 'NOT_YET_VALID',
    });
    expect(store.authenticate('secret-alpha-0001', at('2026-10-02T00:00:00.000Z')).ok).toBe(true);
  });

  it('rejects a revoked credential even while it is otherwise valid', () => {
    const store = new CredentialStore([
      { ...base, expiresAt: '2027-01-01T00:00:00.000Z', revokedAt: '2026-08-15T00:00:00.000Z' },
    ]);
    // Revocation beats a distant expiry: that is the whole point of having it.
    expect(store.authenticate('secret-alpha-0001', at('2026-09-01T00:00:00.000Z'))).toMatchObject({
      ok: false,
      reason: 'REVOKED',
    });
  });

  it('rejects an unknown secret without revealing which credentials exist', () => {
    const store = new CredentialStore([base]);
    const result = store.authenticate('not-the-secret', at('2026-09-01T00:00:00.000Z'));
    expect(result).toEqual({ ok: false, reason: 'UNKNOWN' });
    // No credentialId on an unknown secret: there is nothing to attribute it to.
    expect(result).not.toHaveProperty('credentialId');
  });

  it('supports zero-downtime rotation: two live secrets for one principal', () => {
    // The overlap window is what makes rotation possible without a synchronised cutover.
    const store = new CredentialStore([
      { id: 'svc-web', secret: 'old-secret-0001', role: 'reader', expiresAt: '2026-09-10T00:00:00.000Z' },
      { id: 'svc-web', secret: 'new-secret-0002', role: 'reader', notBefore: '2026-09-01T00:00:00.000Z' },
    ]);

    const during = at('2026-09-05T00:00:00.000Z');
    expect(store.authenticate('old-secret-0001', during).ok).toBe(true);
    expect(store.authenticate('new-secret-0002', during).ok).toBe(true);

    const afterCutover = at('2026-09-15T00:00:00.000Z');
    expect(store.authenticate('old-secret-0001', afterCutover).ok).toBe(false);
    expect(store.authenticate('new-secret-0002', afterCutover).ok).toBe(true);
  });

  it('produces an inventory that flags rotation pressure and never leaks secrets', () => {
    const store = new CredentialStore([
      { ...base, expiresAt: '2026-09-05T00:00:00.000Z' },
      { id: 'svc-batch', secret: 'secret-beta-0002', role: 'writer', expiresAt: '2027-01-01T00:00:00.000Z' },
      { id: 'svc-dead', secret: 'secret-gamma-0003', role: 'admin', revokedAt: '2026-01-01T00:00:00.000Z' },
    ]);

    const inventory = store.inventory(at('2026-09-01T00:00:00.000Z'), 14);

    expect(inventory[0]).toMatchObject({ id: 'svc-web', state: 'active', rotationDue: true, expiresInDays: 4 });
    expect(inventory[1]).toMatchObject({ id: 'svc-batch', state: 'active', rotationDue: false });
    expect(inventory[2]).toMatchObject({ id: 'svc-dead', state: 'revoked' });
    expect(JSON.stringify(inventory)).not.toContain('secret-');
  });
});

describe('credential configuration', () => {
  const env = { DATABASE_PATH: ':memory:' };

  it('parses the full JSON credential form including scope', () => {
    const config = loadConfig({
      ...env,
      API_CREDENTIALS: JSON.stringify([
        {
          id: 'bu-west',
          secret: 'scoped-secret-1',
          role: 'reader',
          expiresAt: '2027-01-01T00:00:00.000Z',
          scope: { resourceIds: ['client-100'] },
          description: 'West desk, one client',
        },
      ]),
    });

    expect(config.credentials).toHaveLength(1);
    expect(config.credentials[0]!.scope).toEqual({ resourceIds: ['client-100'] });
  });

  it('rejects malformed credential configuration at boot', () => {
    expect(() => loadConfig({ ...env, API_CREDENTIALS: 'not json' })).toThrow(/JSON array/);
    expect(() =>
      loadConfig({ ...env, API_CREDENTIALS: JSON.stringify([{ id: 'a', secret: 'short', role: 'reader' }]) }),
    ).toThrow(/at least 8 characters/);
    expect(() =>
      loadConfig({ ...env, API_CREDENTIALS: JSON.stringify([{ id: 'a', secret: 'longenough', role: 'wizard' }]) }),
    ).toThrow(/Invalid API_CREDENTIALS/);
  });

  it('rejects a credential that expires before it becomes valid', () => {
    expect(() =>
      loadConfig({
        ...env,
        API_CREDENTIALS: JSON.stringify([
          {
            id: 'a',
            secret: 'longenough-1',
            role: 'reader',
            notBefore: '2027-01-01T00:00:00.000Z',
            expiresAt: '2026-01-01T00:00:00.000Z',
          },
        ]),
      }),
    ).toThrow(/expires before it becomes valid/);
  });

  it('requires unique secrets but permits a shared id, which is how rotation is expressed', () => {
    const rotating = [
      { id: 'svc', secret: 'secret-one-1', role: 'reader' },
      { id: 'svc', secret: 'secret-two-2', role: 'reader' },
    ];
    expect(() => loadConfig({ ...env, API_CREDENTIALS: JSON.stringify(rotating) })).not.toThrow();

    const duplicated = [
      { id: 'a', secret: 'same-secret-1', role: 'reader' },
      { id: 'b', secret: 'same-secret-1', role: 'admin' },
    ];
    expect(() => loadConfig({ ...env, API_CREDENTIALS: JSON.stringify(duplicated) })).toThrow(/unique/);
  });

  describe('production guards', () => {
    const prod = { ...env, NODE_ENV: 'production' };

    it('refuses the published development keys', () => {
      expect(() => loadConfig({ ...prod, API_KEYS: 'dev-writer-key:writer' })).toThrow(
        /development API keys/,
      );
    });

    it('refuses a credential with no expiry', () => {
      // A credential nobody has to renew is a credential nobody will ever retire.
      expect(() => loadConfig({ ...prod, API_KEYS: 'a-real-secret:writer' })).toThrow(
        /non-expiring credentials/,
      );
    });

    it('refuses a credential whose lifetime exceeds the maximum', () => {
      const tenYears = new Date(Date.now() + 3650 * 86_400_000).toISOString();
      expect(() =>
        loadConfig({
          ...prod,
          API_CREDENTIALS: JSON.stringify([
            { id: 'forever', secret: 'a-real-secret-1', role: 'writer', expiresAt: tenYears },
          ]),
        }),
      ).toThrow(/maximum lifetime/);
    });

    it('accepts a properly bounded production credential', () => {
      const soon = new Date(Date.now() + 30 * 86_400_000).toISOString();
      expect(() =>
        loadConfig({
          ...prod,
          API_CREDENTIALS: JSON.stringify([
            { id: 'svc', secret: 'a-real-secret-1', role: 'writer', expiresAt: soon },
          ]),
        }),
      ).not.toThrow();
    });
  });
});
