import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';

const base = { DATABASE_PATH: ':memory:', API_KEYS: 'k1:writer,k2:admin' };

describe('configuration', () => {
  it('applies documented defaults', () => {
    const config = loadConfig(base);
    expect(config.port).toBe(3000);
    expect(config.retentionWindowDays).toBe(365);
    expect(config.maxClockSkewMs).toBe(300_000);
  });

  it('parses API keys into roles without retaining the secret in the principal label', () => {
    const config = loadConfig({ ...base, API_KEYS: 'supersecretkey:auditor' });
    expect(config.apiKeys[0]!.role).toBe('auditor');
    // The principal is what lands in logs and self-audit events, so it must not be the key.
    expect(config.apiKeys[0]!.principal).not.toContain('supersecretkey');
    expect(config.apiKeys[0]!.principal).toMatch(/^key:auditor:/);
  });

  it('fails at boot on invalid configuration rather than at the first request', () => {
    expect(() => loadConfig({ ...base, PORT: 'not-a-port' })).toThrow(/Invalid configuration/);
    expect(() => loadConfig({ ...base, API_KEYS: 'keywithoutarole' })).toThrow(/expected/);
    expect(() => loadConfig({ ...base, API_KEYS: 'k:wizard' })).toThrow(/Invalid role/);
    expect(() => loadConfig({ ...base, API_KEYS: '' })).toThrow(/at least one key/);
    expect(() => loadConfig({ ...base, API_KEYS: 'dup:reader,dup:admin' })).toThrow(/duplicate/);
    expect(() => loadConfig({ ...base, RETENTION_WINDOW_DAYS: '-5' })).toThrow(
      /Invalid configuration/,
    );
  });

  it('refuses to start in production with the published development keys', () => {
    // .env.example ships these values. Booting production with them would be an open audit log,
    // so this is a refusal rather than a warning nobody reads.
    expect(() =>
      loadConfig({ ...base, NODE_ENV: 'production', API_KEYS: 'dev-writer-key:writer' }),
    ).toThrow(/development API keys/);

    expect(() =>
      loadConfig({ ...base, NODE_ENV: 'production', API_KEYS: 'a-real-secret:writer' }),
    ).not.toThrow();
  });

  it('never lets the default page size exceed the maximum', () => {
    const config = loadConfig({ ...base, DEFAULT_PAGE_SIZE: '500', MAX_PAGE_SIZE: '100' });
    expect(config.defaultPageSize).toBe(100);
  });
});
