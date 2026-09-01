/**
 * Hashing primitives.
 *
 * Deliberately dependency-free and side-effect-free: the offline bundle verifier
 * (`src/cli/verify-bundle.ts`) imports this module and nothing else from the service, which
 * is what makes "independently verifiable" meaningful rather than circular.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** Hash algorithm identifier persisted with every record (see ADR-0001). */
export const HASH_ALGORITHM = 'sha256' as const;

/** The defined predecessor of the first record: the genesis value. */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Domain-separation tags. Without them, a crafted payload could be serialized to collide
 * with a record header digest, letting an attacker substitute one for the other.
 */
export const DOMAIN = {
  record: 'audit-record-v1',
  field: 'audit-field-v1',
  node: 'audit-node-v1',
  payload: 'audit-payload-v1',
  bundle: 'audit-bundle-v1',
} as const;

/**
 * SHA-256 over a domain tag and an ordered list of parts.
 *
 * Parts are length-prefixed so concatenation is unambiguous: without it, ("ab","c") and
 * ("a","bc") hash identically, which is a real substitution attack when one part is
 * attacker-controlled.
 */
export function tagged(domain: string, ...parts: string[]): string {
  const hash = createHash(HASH_ALGORITHM);
  hash.update(domain, 'utf8');
  for (const part of parts) {
    const bytes = Buffer.byteLength(part, 'utf8');
    hash.update(`|${bytes}|`, 'utf8');
    hash.update(part, 'utf8');
  }
  return hash.digest('hex');
}

export function sha256Hex(input: string): string {
  return createHash(HASH_ALGORITHM).update(input, 'utf8').digest('hex');
}

/** 128 bits of salt: enough that a commitment to a low-entropy value stays hiding. */
export function randomSaltHex(bytes = 16): string {
  return randomBytes(bytes).toString('hex');
}

export function isHexDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/** Constant-time comparison, used for digests and API keys so failures leak no timing signal. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
