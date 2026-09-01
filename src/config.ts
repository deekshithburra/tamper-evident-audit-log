/**
 * Configuration, resolved once at startup.
 *
 * Everything the brief calls "configurable" is here, and nothing reads `process.env` outside
 * this module. Invalid configuration fails at boot rather than at the first request: an audit
 * service that starts with a broken retention window and discovers it a month later has
 * already done the damage.
 */

import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_PATH: z.string().min(1).default('./data/audit.db'),
  MAX_CLOCK_SKEW_MS: z.coerce.number().int().min(0).default(5 * 60 * 1000),
  RETENTION_WINDOW_DAYS: z.coerce.number().int().min(0).default(365),
  API_KEYS: z
    .string()
    .default('dev-writer-key:writer,dev-reader-key:reader,dev-auditor-key:auditor,dev-admin-key:admin'),
  MAX_PAGE_SIZE: z.coerce.number().int().min(1).max(1000).default(200),
  DEFAULT_PAGE_SIZE: z.coerce.number().int().min(1).max(1000).default(50),
});

export type Role = 'writer' | 'reader' | 'auditor' | 'admin';
export const ROLES: readonly Role[] = ['writer', 'reader', 'auditor', 'admin'] as const;

export interface ApiKeyEntry {
  key: string;
  role: Role;
  /** Stable, non-secret label used as the actor in self-audit events and logs. */
  principal: string;
}

export interface Config {
  env: 'development' | 'test' | 'production';
  port: number;
  logLevel: string;
  databasePath: string;
  maxClockSkewMs: number;
  retentionWindowDays: number;
  apiKeys: ApiKeyEntry[];
  maxPageSize: number;
  defaultPageSize: number;
}

function parseApiKeys(raw: string): ApiKeyEntry[] {
  const entries = raw
    .split(',')
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const separator = pair.lastIndexOf(':');
      if (separator < 1) {
        throw new Error(`Invalid API_KEYS entry "${pair}": expected "<key>:<role>"`);
      }
      const key = pair.slice(0, separator);
      const role = pair.slice(separator + 1) as Role;
      if (!ROLES.includes(role)) {
        throw new Error(`Invalid role "${role}" in API_KEYS: expected one of ${ROLES.join(', ')}`);
      }
      // The principal is derived from the key so logs and self-audit events can attribute an
      // action without ever recording the secret itself.
      return { key, role, principal: `key:${role}:${key.slice(0, 4)}...` };
    });

  if (entries.length === 0) throw new Error('API_KEYS must define at least one key');
  const unique = new Set(entries.map((entry) => entry.key));
  if (unique.size !== entries.length) throw new Error('API_KEYS contains duplicate keys');
  return entries;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const values = parsed.data;

  const apiKeys = parseApiKeys(values.API_KEYS);

  // The development defaults are published in .env.example. Booting production with them would
  // be an open audit log, so refuse rather than warn.
  if (values.NODE_ENV === 'production' && apiKeys.some((entry) => entry.key.startsWith('dev-'))) {
    throw new Error('Refusing to start in production with development API keys configured');
  }

  return {
    env: values.NODE_ENV,
    port: values.PORT,
    logLevel: values.LOG_LEVEL,
    databasePath: values.DATABASE_PATH,
    maxClockSkewMs: values.MAX_CLOCK_SKEW_MS,
    retentionWindowDays: values.RETENTION_WINDOW_DAYS,
    apiKeys,
    maxPageSize: values.MAX_PAGE_SIZE,
    defaultPageSize: Math.min(values.DEFAULT_PAGE_SIZE, values.MAX_PAGE_SIZE),
  };
}
