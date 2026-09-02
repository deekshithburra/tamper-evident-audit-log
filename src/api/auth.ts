/**
 * Authentication and authorization.
 *
 * Three layers, and they answer three different questions:
 *
 *   authenticate()      who is calling, and is their credential currently usable?
 *   requireCapability() may this principal perform this kind of operation?  (RBAC)
 *   AccessScope         may this principal reach this particular object?    (object-level)
 *
 * The third is the one most APIs omit, and its absence is Broken Object Level Authorization.
 * A role check alone would let any `reader` credential read every record in the log. Scope is
 * carried on the Principal and enforced in the service layer - see `domain/access-scope.ts`.
 */

import type { NextFunction, Request, Response } from 'express';
import { AppError, type ErrorCode } from '../domain/errors.js';
import type { AccessScope } from '../domain/access-scope.js';
import type { CredentialRejection, CredentialStore } from './credentials.js';
import type { Config, Role } from '../config.js';

export interface Principal {
  role: Role;
  /** Non-secret credential id; used as the actor on self-audit events. */
  id: string;
  scope?: AccessScope;
  expiresAt?: string;
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
  writer: ['events:write', 'identity:read'],
  reader: ['events:read', 'identity:read'],
  auditor: ['events:read', 'chain:verify', 'records:export', 'reports:read', 'identity:read'],
  admin: [
    'events:write',
    'events:read',
    'chain:verify',
    'records:export',
    'reports:read',
    'records:redact',
    'retention:apply',
    'identity:read',
    'credentials:read',
  ],
} as const satisfies Record<Role, readonly string[]>;

export type Capability = (typeof CAPABILITIES)[Role][number];

const REJECTION_RESPONSE: Record<
  CredentialRejection,
  { code: ErrorCode; message: string }
> = {
  UNKNOWN: { code: 'UNAUTHENTICATED', message: 'Unrecognised API key' },
  EXPIRED: {
    code: 'CREDENTIAL_EXPIRED',
    message: 'This credential has expired. Request a replacement and retry with the new secret.',
  },
  REVOKED: {
    code: 'CREDENTIAL_REVOKED',
    message: 'This credential has been revoked.',
  },
  NOT_YET_VALID: {
    code: 'CREDENTIAL_NOT_YET_VALID',
    message: 'This credential is staged but not yet active.',
  },
};

export function authenticate(config: Config, store: CredentialStore, now: () => Date = () => new Date()) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.header('authorization');
    const apiKeyHeader = req.header('x-api-key');
    const presented =
      apiKeyHeader ?? (header?.toLowerCase().startsWith('bearer ') ? header.slice(7) : undefined);

    if (presented === undefined || presented.length === 0) {
      next(AppError.unauthenticated('Provide an API key via the X-API-Key or Authorization header'));
      return;
    }

    const result = store.authenticate(presented, now());

    if (!result.ok) {
      const response = REJECTION_RESPONSE[result.reason];
      next(
        response.code === 'UNAUTHENTICATED'
          ? AppError.unauthenticated(response.message)
          : AppError.credentialLapsed(response.code, response.message),
      );
      return;
    }

    const { credential, expiresInMs } = result;

    // Expiry is visible on every successful response, so a client can automate rotation instead
    // of discovering the lapse as a production outage.
    if (credential.expiresAt !== undefined) {
      res.set('X-Credential-Expires-At', credential.expiresAt);
      const warnMs = config.credentialRotationWarningDays * 86_400_000;
      if (expiresInMs !== null && expiresInMs <= warnMs) {
        res.set('X-Credential-Rotation-Due', 'true');
        res.set(
          'Warning',
          `299 - "API credential ${credential.id} expires at ${credential.expiresAt}; rotate it"`,
        );
      }
    }

    req.principal = {
      role: credential.role,
      id: credential.id,
      ...(credential.scope === undefined ? {} : { scope: credential.scope }),
      ...(credential.expiresAt === undefined ? {} : { expiresAt: credential.expiresAt }),
    };
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
