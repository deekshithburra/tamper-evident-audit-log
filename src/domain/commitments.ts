/**
 * Structured payload commitments (ADR-0003).
 *
 * The record hash never covers payload plaintext directly. Instead the payload is flattened
 * into leaf paths; each leaf is committed to under its own random salt; the leaves are folded
 * into a Merkle root; and the *root* is what the record hash covers.
 *
 * That indirection is what makes redaction possible at all: destroying a value and its salt
 * leaves the leaf digest, the root, and therefore the record hash and the whole chain
 * completely unchanged.
 */

import { canonicalize, type JsonValue } from './canonical.js';
import { DOMAIN, randomSaltHex, tagged } from './hash.js';
import { AppError } from './errors.js';

/** Guardrails: a hash chain is an unbounded, permanent write surface. Bound it at the door. */
export const LIMITS = {
  maxLeaves: 512,
  maxDepth: 12,
  maxPayloadBytes: 64 * 1024,
} as const;

export interface Leaf {
  /** Escaped path, e.g. `account.number` or `items.0.id`. */
  path: string;
  /** Salted commitment to the value at `path`. Retained forever, including after redaction. */
  digest: string;
}

export interface PayloadCommitment {
  root: string;
  leaves: Leaf[];
  /** path -> salt. Destroyed for a path when that path is redacted. */
  salts: Record<string, string>;
}

/**
 * Path segments are escaped so that a key containing a literal '.' cannot be confused with
 * nesting. Two distinct payloads must never produce the same leaf path.
 *   '~' -> '~0'   '.' -> '~1'
 */
export function escapeSegment(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\./g, '~1');
}

export function unescapeSegment(segment: string): string {
  return segment.replace(/~1/g, '.').replace(/~0/g, '~');
}

/**
 * Flatten to leaves. Scalars become leaves, and an empty object or array becomes a leaf
 * committing to itself, so payload *shape* is committed too. Without that, a payload with an
 * empty container would produce no leaf for it at all and the container could be added or
 * removed without changing the root.
 */
export function flatten(value: unknown, prefix = '', depth = 0): Array<[string, JsonValue]> {
  if (depth > LIMITS.maxDepth) {
    throw AppError.validation(`Payload nesting exceeds maximum depth of ${LIMITS.maxDepth}`);
  }

  if (value === null || typeof value !== 'object') {
    return [[prefix, value as JsonValue]];
  }

  if (Array.isArray(value)) {
    // An empty container commits to itself; canonical JSON distinguishes `[]` from `{}` from
    // any string, so no forged sentinel value can collide with it.
    if (value.length === 0) return [[prefix, [] as JsonValue]];
    return value.flatMap((item, i) => flatten(item, join(prefix, String(i)), depth + 1));
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return [[prefix, {} as JsonValue]];
  return entries.flatMap(([key, item]) =>
    flatten(item, join(prefix, escapeSegment(key)), depth + 1),
  );
}

function join(prefix: string, segment: string): string {
  return prefix === '' ? segment : `${prefix}.${segment}`;
}

/** leaf = H(field-tag, path, salt, canonical(value)) */
export function leafDigest(path: string, salt: string, value: JsonValue): string {
  return tagged(DOMAIN.field, path, salt, canonicalize(value));
}

/**
 * RFC 6962-style Merkle fold over path-sorted leaves. Interior nodes carry their own domain
 * tag so a leaf digest can never be presented as an interior node. An odd node is promoted
 * unchanged; the leaf *count* is bound into the final root, which removes the second-preimage
 * ambiguity that promotion would otherwise introduce.
 */
export function merkleRoot(leaves: Leaf[]): string {
  const sorted = [...leaves].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  let level = sorted.map((leaf) => leaf.digest);
  if (level.length === 0) {
    return tagged(DOMAIN.payload, '0', tagged(DOMAIN.node, 'empty'));
  }

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as string;
      const right = level[i + 1];
      next.push(right === undefined ? left : tagged(DOMAIN.node, left, right));
    }
    level = next;
  }

  return tagged(DOMAIN.payload, String(sorted.length), level[0] as string);
}

/** Commit to a payload at write time, generating one fresh salt per leaf. */
export function commitPayload(payload: unknown): PayloadCommitment {
  const serialized = canonicalize(payload);
  if (Buffer.byteLength(serialized, 'utf8') > LIMITS.maxPayloadBytes) {
    throw AppError.tooLarge(
      `Payload exceeds maximum size of ${LIMITS.maxPayloadBytes} bytes`,
    );
  }

  const flat = flatten(payload);
  if (flat.length > LIMITS.maxLeaves) {
    throw AppError.validation(
      `Payload has ${flat.length} leaf fields, exceeding the maximum of ${LIMITS.maxLeaves}`,
    );
  }

  const salts: Record<string, string> = {};
  const leaves: Leaf[] = flat.map(([path, value]) => {
    const salt = randomSaltHex();
    salts[path] = salt;
    return { path, digest: leafDigest(path, salt, value) };
  });

  return { root: merkleRoot(leaves), leaves, salts };
}

/**
 * Recompute the commitment for a stored record, re-deriving every leaf whose plaintext and
 * salt are still present and accepting the stored digest for leaves that were redacted or
 * archived.
 *
 * This is the heart of chain-preserving redaction. A retained leaf is not "trusted blindly":
 * it is bound into the root, which is bound into `recordHash`, which is bound into every
 * subsequent record. An operator who alters a retained leaf to hide what was there breaks the
 * chain from that record onward, exactly like any other tamper.
 */
export function recomputeRoot(input: {
  storedLeaves: Leaf[];
  salts: Record<string, string>;
  payload: unknown | null;
}): { root: string; mismatchedPaths: string[] } {
  const mismatchedPaths: string[] = [];
  const present = new Map<string, JsonValue>(
    input.payload === null || input.payload === undefined ? [] : flatten(input.payload),
  );

  const leaves: Leaf[] = input.storedLeaves.map((leaf) => {
    const salt = input.salts[leaf.path];
    if (salt === undefined || !present.has(leaf.path)) {
      // Value and/or salt destroyed by redaction or archival: the stored digest stands in.
      return leaf;
    }
    const recomputed = leafDigest(leaf.path, salt, present.get(leaf.path) as JsonValue);
    if (recomputed !== leaf.digest) mismatchedPaths.push(leaf.path);
    return { path: leaf.path, digest: recomputed };
  });

  // A leaf present in the plaintext but absent from the stored leaf set means the payload
  // gained a field after the fact: tamper, not redaction.
  //
  // The injected leaf must be folded into the computed root, not merely reported. Otherwise a
  // verifier that compares roots (which is what the chain check does) would see an unchanged
  // root and pass, and only a caller that also inspected `mismatchedPaths` would catch it.
  // Detection must live in the value the chain covers, not in a side channel.
  const knownPaths = new Set(input.storedLeaves.map((leaf) => leaf.path));
  for (const [path, value] of present) {
    if (knownPaths.has(path)) continue;
    mismatchedPaths.push(path);
    leaves.push({ path, digest: leafDigest(path, input.salts[path] ?? 'unsalted', value) });
  }

  return { root: merkleRoot(leaves), mismatchedPaths };
}
