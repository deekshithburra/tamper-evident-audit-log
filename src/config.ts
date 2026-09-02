/**
 * Configuration, resolved once at startup.
 *
 * Everything the brief calls "configurable" is here, and nothing reads `process.env` outside
 * this module. Invalid configuration fails at boot rather than at the first request: an audit
 * service that starts with a broken retention window and discovers it a month later has
 * already done the damage.
 *
 * The production guards at the bottom of `loadConfig` are the part worth reading. Each one is
 * a refusal rather than a warning, because a warning in a startup log is a control nobody
 * enforces.
 */

import { z } from 'zod';
import type { AccessScope } from './domain/access-scope.js';
import type { Credential } from './api/credentials.js';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_PATH: z.string().min(1).default('./data/audit.db'),
  MAX_CLOCK_SKEW_MS: z.coerce.number().int().min(0).default(5 * 60 * 1000),
  RETENTION_WINDOW_DAYS: z.coerce.number().int().min(0).default(365),

  /** Simple form, for local development: comma-separated `secret:role` pairs. */
  API_KEYS: z
    .string()
    .default('dev-writer-key:writer,dev-reader-key:reader,dev-auditor-key:auditor,dev-admin-key:admin'),
  /** Full form: a JSON array of credentials with lifecycle and scope. Wins where both define a secret. */
  API_CREDENTIALS: z.string().optional(),

  /** Credentials expiring within this many days are flagged as rotation-due. */
  CREDENTIAL_ROTATION_WARNING_DAYS: z.coerce.number().int().min(0).max(365).default(14),
  /** Maximum permitted credential lifetime. Enforced at boot in production. */
  MAX_CREDENTIAL_LIFETIME_DAYS: z.coerce.number().int().min(1).max(3650).default(90),

  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((value) => value === 'true'),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60_000),
  /** Per-credential ceilings per window, by cost class. */
  RATE_LIMIT_MAX_WRITE: z.coerce.number().int().min(1).default(1200),
  RATE_LIMIT_MAX_READ: z.coerce.number().int().min(1).default(600),
  /** Chain verification, export and reporting are O(n) over the log; they get their own budget. */
  RATE_LIMIT_MAX_EXPENSIVE: z.coerce.number().int().min(1).default(30),

  MAX_PAGE_SIZE: z.coerce.number().int().min(1).max(1000).default(200),
  DEFAULT_PAGE_SIZE: z.coerce.number().int().min(1).max(1000).default(50),
});

export type Role = 'writer' | 'reader' | 'auditor' | 'admin';
export const ROLES: readonly Role[] = ['writer', 'reader', 'auditor', 'admin'] as const;

export type RateLimitClass = 'write' | 'read' | 'expensive';

export interface RateLimitConfig {
  enabled: boolean;
  windowMs: number;
  limits: Record<RateLimitClass, number>;
}

export interface Config {
  env: 'development' | 'test' | 'production';
  port: number;
  logLevel: string;
  databasePath: string;
  maxClockSkewMs: number;
  retentionWindowDays: number;
  credentials: Credential[];
  credentialRotationWarningDays: number;
  maxCredentialLifetimeDays: number;
  rateLimit: RateLimitConfig;
  maxPageSize: number;
  defaultPageSize: number;
}

const scopeSchema: z.ZodType<AccessScope> = z
  .object({
    actorIds: z.array(z.string().min(1)).min(1).optional(),
    resourceTypes: z.array(z.string().min(1)).min(1).optional(),
    resourceIds: z.array(z.string().min(1)).min(1).optional(),
  })
  .strict();

const credentialSchema = z
  .object({
    id: z.string().min(1).max(128),
    secret: z.string().min(8, 'a credential secret must be at least 8 characters'),
    role: z.enum(['writer', 'reader', 'auditor', 'admin']),
    notBefore: z.string().datetime({ offset: true }).optional(),
    expiresAt: z.string().datetime({ offset: true }).optional(),
    revokedAt: z.string().datetime({ offset: true }).optional(),
    scope: scopeSchema.optional(),
    description: z.string().max(256).optional(),
  })
  .strict();

/** Legacy/simple form. Produces a non-expiring credential, which production then refuses. */
function parseSimpleKeys(raw: string): Credential[] {
  return raw
    .split(',')
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const separator = pair.lastIndexOf(':');
      if (separator < 1) {
        throw new Error(`Invalid API_KEYS entry "${pair}": expected "<secret>:<role>"`);
      }
      const secret = pair.slice(0, separator);
      const role = pair.slice(separator + 1) as Role;
      if (!ROLES.includes(role)) {
        throw new Error(`Invalid role "${role}" in API_KEYS: expected one of ${ROLES.join(', ')}`);
      }
      // The id is derived from the role and a secret prefix so logs and self-audit events can
      // attribute an action without ever recording the secret itself.
      return { id: `key:${role}:${secret.slice(0, 4)}...`, secret, role };
    });
}

function parseJsonCredentials(raw: string): Credential[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('API_CREDENTIALS must be a JSON array of credential objects');
  }
  const result = z.array(credentialSchema).min(1).safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `[${issue.path.join('.')}] ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid API_CREDENTIALS: ${issues}`);
  }
  return result.data as Credential[];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const values = parsed.data;

  const credentials =
    values.API_CREDENTIALS === undefined
      ? parseSimpleKeys(values.API_KEYS)
      : parseJsonCredentials(values.API_CREDENTIALS);

  if (credentials.length === 0) throw new Error('At least one credential must be configured');

  // Secrets must be unique; ids need not be. Two credentials sharing an id is how a
  // zero-downtime rotation is expressed: same principal, two live secrets, overlapping windows.
  const secrets = new Set(credentials.map((credential) => credential.secret));
  if (secrets.size !== credentials.length) {
    throw new Error('Credential secrets must be unique');
  }

  for (const credential of credentials) {
    if (
      credential.notBefore !== undefined &&
      credential.expiresAt !== undefined &&
      Date.parse(credential.notBefore) >= Date.parse(credential.expiresAt)
    ) {
      throw new Error(`Credential "${credential.id}" expires before it becomes valid`);
    }
  }

  const production = values.NODE_ENV === 'production';
  if (production) {
    // The development defaults are published in .env.example. Booting production with them
    // would be an open audit log, so refuse rather than warn.
    if (credentials.some((credential) => credential.secret.startsWith('dev-'))) {
      throw new Error('Refusing to start in production with development API keys configured');
    }
    // A credential with no expiry is a credential nobody will ever retire.
    const immortal = credentials.filter((credential) => credential.expiresAt === undefined);
    if (immortal.length > 0) {
      throw new Error(
        `Refusing to start in production with non-expiring credentials: ${immortal
          .map((credential) => credential.id)
          .join(', ')}. Set expiresAt on every credential.`,
      );
    }
    // ...and one with a ten-year expiry is the same thing wearing a hat.
    const maxLifetimeMs = values.MAX_CREDENTIAL_LIFETIME_DAYS * 86_400_000;
    const overlong = credentials.filter((credential) => {
      const start = credential.notBefore === undefined ? Date.now() : Date.parse(credential.notBefore);
      return Date.parse(credential.expiresAt as string) - start > maxLifetimeMs;
    });
    if (overlong.length > 0) {
      throw new Error(
        `Refusing to start in production with credentials exceeding the ${values.MAX_CREDENTIAL_LIFETIME_DAYS}-day ` +
          `maximum lifetime: ${overlong.map((credential) => credential.id).join(', ')}`,
      );
    }
  }

  return {
    env: values.NODE_ENV,
    port: values.PORT,
    logLevel: values.LOG_LEVEL,
    databasePath: values.DATABASE_PATH,
    maxClockSkewMs: values.MAX_CLOCK_SKEW_MS,
    retentionWindowDays: values.RETENTION_WINDOW_DAYS,
    credentials,
    credentialRotationWarningDays: values.CREDENTIAL_ROTATION_WARNING_DAYS,
    maxCredentialLifetimeDays: values.MAX_CREDENTIAL_LIFETIME_DAYS,
    rateLimit: {
      enabled: values.RATE_LIMIT_ENABLED,
      windowMs: values.RATE_LIMIT_WINDOW_MS,
      limits: {
        write: values.RATE_LIMIT_MAX_WRITE,
        read: values.RATE_LIMIT_MAX_READ,
        expensive: values.RATE_LIMIT_MAX_EXPENSIVE,
      },
    },
    maxPageSize: values.MAX_PAGE_SIZE,
    defaultPageSize: Math.min(values.DEFAULT_PAGE_SIZE, values.MAX_PAGE_SIZE),
  };
}
