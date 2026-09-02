/**
 * Credential lifecycle.
 *
 * The first version of this service treated an API key as a permanent fact: a string that was
 * either in the config or not. That is the shape of credential handling that produces
 * ten-year-old keys nobody can attribute or retire. A credential here has a lifetime and a
 * state, and every one of those is checked on every request rather than only at boot:
 *
 *   notBefore   - staged ahead of a cutover, inert until then
 *   expiresAt   - stops working on its own, without anyone remembering to remove it
 *   revokedAt   - killed immediately, ahead of its expiry
 *   scope       - what objects it may reach at all (see domain/access-scope.ts)
 *
 * **Rotation** is why two credentials may share an `id`. To rotate without downtime you issue a
 * second secret for the same principal, let both work during an overlap window, cut traffic
 * over, then let the old one expire. Uniqueness is therefore enforced on the *secret*, not the
 * id - the id is the principal, the secret is one of possibly two keys that speak for it.
 *
 * What this is not: a token service. There is no issuance endpoint, no signing key, no refresh
 * flow. Production would use short-lived OIDC tokens or mTLS, and this module is the seam that
 * gets replaced - `authenticate()` returns a Principal and nothing above it cares how the
 * Principal was established.
 */

import { safeEqual } from '../domain/hash.js';
import type { AccessScope } from '../domain/access-scope.js';
import type { Role } from '../config.js';

export interface Credential {
  /** Non-secret principal label. Appears in logs and in self-audit events. */
  id: string;
  secret: string;
  role: Role;
  /** Inert before this instant. Absent means active immediately. */
  notBefore?: string;
  /** Stops working at this instant. Absent means non-expiring (refused in production). */
  expiresAt?: string;
  /** Killed at this instant regardless of expiry. */
  revokedAt?: string;
  scope?: AccessScope;
  description?: string;
}

export type CredentialRejection =
  | 'UNKNOWN'
  | 'EXPIRED'
  | 'NOT_YET_VALID'
  | 'REVOKED';

export interface AuthenticationSuccess {
  ok: true;
  credential: Credential;
  /** Milliseconds until expiry, or null for a non-expiring credential. */
  expiresInMs: number | null;
}

export interface AuthenticationFailure {
  ok: false;
  reason: CredentialRejection;
  /** Present when the secret matched but the credential was not usable - safe to log. */
  credentialId?: string;
}

export type AuthenticationResult = AuthenticationSuccess | AuthenticationFailure;

export class CredentialStore {
  private readonly credentials: readonly Credential[];

  constructor(credentials: readonly Credential[]) {
    this.credentials = credentials;
  }

  /**
   * Resolve a presented secret.
   *
   * Every credential is compared, and every comparison is constant-time. Returning early on a
   * match would make the response time depend on the matched key's position in the list, which
   * is a (weak, but free to avoid) oracle. The lifecycle checks happen after the scan for the
   * same reason: an expired key and an unknown key must cost the same.
   */
  authenticate(presented: string, now: Date = new Date()): AuthenticationResult {
    let matched: Credential | undefined;
    for (const credential of this.credentials) {
      if (safeEqual(credential.secret, presented)) matched = credential;
    }

    if (matched === undefined) return { ok: false, reason: 'UNKNOWN' };

    const at = now.getTime();
    if (matched.revokedAt !== undefined && at >= Date.parse(matched.revokedAt)) {
      return { ok: false, reason: 'REVOKED', credentialId: matched.id };
    }
    if (matched.notBefore !== undefined && at < Date.parse(matched.notBefore)) {
      return { ok: false, reason: 'NOT_YET_VALID', credentialId: matched.id };
    }
    if (matched.expiresAt !== undefined && at >= Date.parse(matched.expiresAt)) {
      return { ok: false, reason: 'EXPIRED', credentialId: matched.id };
    }

    return {
      ok: true,
      credential: matched,
      expiresInMs: matched.expiresAt === undefined ? null : Date.parse(matched.expiresAt) - at,
    };
  }

  /**
   * Operational view of the credential inventory: what exists, what state it is in, and what
   * is about to lapse. Surfaced on `/auth/credentials` for `admin` so that "which keys are
   * about to expire" is answerable without reading deployment config.
   *
   * Secrets are never included, at any verbosity.
   */
  inventory(now: Date = new Date(), warnWithinDays = 14) {
    const at = now.getTime();
    return this.credentials.map((credential) => {
      const expiresAt = credential.expiresAt === undefined ? null : Date.parse(credential.expiresAt);
      const state = this.stateOf(credential, at);
      return {
        id: credential.id,
        role: credential.role,
        state,
        notBefore: credential.notBefore ?? null,
        expiresAt: credential.expiresAt ?? null,
        revokedAt: credential.revokedAt ?? null,
        expiresInDays: expiresAt === null ? null : Math.floor((expiresAt - at) / 86_400_000),
        rotationDue:
          state === 'active' &&
          expiresAt !== null &&
          expiresAt - at <= warnWithinDays * 86_400_000,
        scoped: credential.scope !== undefined,
        description: credential.description ?? null,
      };
    });
  }

  private stateOf(credential: Credential, at: number): 'active' | 'expired' | 'revoked' | 'pending' {
    if (credential.revokedAt !== undefined && at >= Date.parse(credential.revokedAt)) return 'revoked';
    if (credential.notBefore !== undefined && at < Date.parse(credential.notBefore)) return 'pending';
    if (credential.expiresAt !== undefined && at >= Date.parse(credential.expiresAt)) return 'expired';
    return 'active';
  }

  get size(): number {
    return this.credentials.length;
  }
}
