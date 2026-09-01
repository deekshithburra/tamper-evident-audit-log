/**
 * Authentication and role-based authorization.
 *
 * API keys are a prototype-grade mechanism, chosen deliberately and with its limits stated in
 * `docs/ARCHITECTURE.md` §6: they are bearer secrets with no expiry, no rotation and no
 * per-request proof of possession. In production this is mTLS or OIDC-issued short-lived
 * tokens. What is *not* prototype-grade, and would be a real defect if skipped, is the
 * least-privilege split: nothing that can write can also redact.
 */

import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../domain/errors.js';
import { safeEqual } from '../domain/hash.js';
import type { ApiKeyEntry, Config, Role } from '../config.js';

export interface Principal {
  role: Role;
  id: string;
}

declare module 'express-serve-static-core' {
  interface Request {
    principal?: Principal;
  }
}

/**
 * Role capabilities.
 *
 * `writer` cannot read; `reader` cannot verify; only `admin` can redact or run retention.
 * Separating write from read matters because a compromised event producer - the most exposed
 * component, since it lives in every application - should not be able to read the audit
 * history it contributes to.
 */
export const CAPABILITIES = {
  writer: ['events:write'],
  reader: ['events:read'],
  auditor: ['events:read', 'chain:verify', 'records:export', 'reports:read'],
  admin: [
    'events:write',
    'events:read',
    'chain:verify',
    'records:export',
    'reports:read',
    'records:redact',
    'retention:apply',
  ],
} as const satisfies Record<Role, readonly string[]>;

export type Capability = (typeof CAPABILITIES)[Role][number];

export function authenticate(config: Config) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const header = req.header('authorization');
    const apiKeyHeader = req.header('x-api-key');
    const presented =
      apiKeyHeader ?? (header?.toLowerCase().startsWith('bearer ') ? header.slice(7) : undefined);

    if (presented === undefined || presented.length === 0) {
      next(AppError.unauthenticated('Provide an API key via the X-API-Key or Authorization header'));
      return;
    }

    // Every configured key is compared, and each comparison is constant-time, so neither the
    // number of comparisons nor their duration depends on how much of the key was correct.
    let matched: ApiKeyEntry | undefined;
    for (const entry of config.apiKeys) {
      if (safeEqual(entry.key, presented)) matched = entry;
    }

    if (matched === undefined) {
      next(AppError.unauthenticated('Unrecognised API key'));
      return;
    }

    req.principal = { role: matched.role, id: matched.principal };
    next();
  };
}

export function requireCapability(capability: string) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const principal = req.principal;
    if (principal === undefined) {
      next(AppError.unauthenticated());
      return;
    }
    const granted = CAPABILITIES[principal.role] as readonly string[];
    if (!granted.includes(capability)) {
      next(
        AppError.forbidden(
          `Role "${principal.role}" lacks the "${capability}" capability required for this endpoint`,
        ),
      );
      return;
    }
    next();
  };
}
