/**
 * The audit record and its hash (ADR-0001).
 *
 * `computeRecordHash` is a pure function of exactly the fields listed in `HASHED_FIELDS`.
 * That list is the security boundary of the whole system: a field inside it cannot be changed
 * without detection, and a field outside it can. Every column added to the schema has to be
 * argued into or out of this list deliberately.
 */

import { canonicalize } from './canonical.js';
import { DOMAIN, GENESIS_HASH, HASH_ALGORITHM, tagged } from './hash.js';
import type { Leaf } from './commitments.js';

export type LifecycleState = 'active' | 'archived';

/** The hashed core of a record: everything covered by `recordHash`. */
export interface RecordCore {
  /** Monotonic chain position, assigned by the server. Position is part of the guarantee. */
  seq: number;
  /** Stable public identifier (UUID), safe to expose and reference externally. */
  eventId: string;
  eventType: string;
  actorId: string;
  resourceType: string;
  resourceId: string;
  /** Caller-supplied (or defaulted) time the event happened. See REQUIREMENTS.md 3.1. */
  occurredAt: string;
  /** Server-assigned time the event was durably recorded. Never caller-controlled. */
  recordedAt: string;
  /** Merkle root over the salted per-field payload commitments. */
  payloadRoot: string;
  /** `recordHash` of seq-1, or the genesis value for seq 1. */
  prevHash: string;
  /** Hash algorithm, hashed so an algorithm migration cannot be applied retroactively. */
  alg: string;
}

/** A record as stored and as returned by the API. */
export interface StoredRecord extends RecordCore {
  recordHash: string;
  lifecycleState: LifecycleState;
  archivedAt: string | null;
  /** Absent (null) once redacted or archived. */
  payload: Record<string, unknown> | null;
  leaves: Leaf[];
  salts: Record<string, string>;
  redactions: RedactionMark[];
}

export interface RedactionMark {
  path: string;
  redactedAt: string;
  redactedBy: string;
  reason: string;
}

/**
 * The exact, ordered set of fields covered by `recordHash`.
 *
 * Deliberately excluded: `lifecycleState`, `archivedAt`, `redactions`, `payload` plaintext and
 * `salts`. Those are the only things retention and redaction are permitted to touch, which is
 * precisely why those operations cannot break the chain (ADR-0003, ADR-0004).
 */
export const HASHED_FIELDS = [
  'seq',
  'eventId',
  'eventType',
  'actorId',
  'resourceType',
  'resourceId',
  'occurredAt',
  'recordedAt',
  'payloadRoot',
  'prevHash',
  'alg',
] as const satisfies ReadonlyArray<keyof RecordCore>;

export function computeRecordHash(core: RecordCore): string {
  const projection: Record<string, unknown> = {};
  for (const field of HASHED_FIELDS) projection[field] = core[field];
  return tagged(DOMAIN.record, canonicalize(projection));
}

export function coreOf(record: RecordCore): RecordCore {
  return {
    seq: record.seq,
    eventId: record.eventId,
    eventType: record.eventType,
    actorId: record.actorId,
    resourceType: record.resourceType,
    resourceId: record.resourceId,
    occurredAt: record.occurredAt,
    recordedAt: record.recordedAt,
    payloadRoot: record.payloadRoot,
    prevHash: record.prevHash,
    alg: record.alg,
  };
}

export { GENESIS_HASH, HASH_ALGORITHM };
