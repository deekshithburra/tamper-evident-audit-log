/**
 * Chain verification.
 *
 * Pure with respect to storage: it consumes an iterable of records, so the same code verifies
 * the live database, a query slice, and an exported bundle. That reuse is deliberate - a
 * verifier that only works against our own database is not evidence of anything.
 *
 * The brief asks for the *type* of violation, not just pass/fail, because the type is what an
 * investigator acts on: a content mismatch means someone edited a record, a link mismatch
 * means records were reordered or spliced, a gap means records were removed outright.
 */

import { recomputeRoot } from '../domain/commitments.js';
import { GENESIS_HASH, HASH_ALGORITHM, computeRecordHash, coreOf, type StoredRecord } from '../domain/record.js';

export type ViolationType =
  /** First record does not link to the defined genesis value: history was truncated at the head. */
  | 'GENESIS_MISMATCH'
  /** A sequence number is missing: records were deleted from the middle of the chain. */
  | 'SEQUENCE_GAP'
  /** prevHash does not match the predecessor's recordHash: records spliced or reordered. */
  | 'LINK_MISMATCH'
  /** Stored recordHash does not match a recomputation of the record's own hashed fields. */
  | 'CONTENT_HASH_MISMATCH'
  /** Payload no longer matches its committed Merkle root: a field value was altered. */
  | 'PAYLOAD_ROOT_MISMATCH'
  /** Record claims a hash algorithm this verifier does not implement. */
  | 'UNSUPPORTED_ALGORITHM';

export interface Violation {
  seq: number;
  eventId: string;
  type: ViolationType;
  message: string;
  expected?: string;
  actual?: string;
  /** For PAYLOAD_ROOT_MISMATCH: which payload fields failed to re-derive. */
  paths?: string[];
}

export interface VerificationReport {
  intact: boolean;
  verifiedAt: string;
  recordsChecked: number;
  range: { fromSeq: number | null; toSeq: number | null };
  chainHead: string | null;
  /** The record at which the chain first became untrustworthy. Null when intact. */
  firstViolation: Violation | null;
  /** Subsequent violations, capped: a break cascades, so the tail is rarely informative. */
  furtherViolations: Violation[];
  totalViolations: number;
  durationMs: number;
}

const MAX_REPORTED_VIOLATIONS = 10;

export interface VerifyOptions {
  /** Hash the predecessor of the first inspected record instead of expecting genesis. Used
   *  when verifying a slice (e.g. an exported bundle) rather than the whole chain. */
  expectedFirstPrevHash?: string;
  /** Stop walking after the first violation. Cheap health check for a monitoring probe. */
  stopAtFirstViolation?: boolean;
}

export function verifyChain(
  records: Iterable<StoredRecord>,
  options: VerifyOptions = {},
): VerificationReport {
  const startedAt = Date.now();
  const violations: Violation[] = [];

  let previous: StoredRecord | null = null;
  let recordsChecked = 0;
  let fromSeq: number | null = null;
  let toSeq: number | null = null;
  let chainHead: string | null = null;

  for (const record of records) {
    recordsChecked += 1;
    if (fromSeq === null) fromSeq = record.seq;
    toSeq = record.seq;
    chainHead = record.recordHash;

    const report = (violation: Omit<Violation, 'seq' | 'eventId'>): void => {
      violations.push({ seq: record.seq, eventId: record.eventId, ...violation });
    };

    if (record.alg !== HASH_ALGORITHM) {
      report({
        type: 'UNSUPPORTED_ALGORITHM',
        message: `Record declares hash algorithm "${record.alg}", which this verifier cannot check`,
        expected: HASH_ALGORITHM,
        actual: record.alg,
      });
      if (options.stopAtFirstViolation) break;
      previous = record;
      continue;
    }

    // 1. Structural: is this record where it claims to be in the sequence?
    if (previous === null) {
      const expectedPrev = options.expectedFirstPrevHash ?? GENESIS_HASH;
      if (record.prevHash !== expectedPrev) {
        report({
          type: options.expectedFirstPrevHash === undefined ? 'GENESIS_MISMATCH' : 'LINK_MISMATCH',
          message:
            options.expectedFirstPrevHash === undefined
              ? 'First record does not link to the genesis value: the head of the chain was altered or removed'
              : 'First record of this slice does not link to the expected predecessor',
          expected: expectedPrev,
          actual: record.prevHash,
        });
      }
    } else {
      if (record.seq !== previous.seq + 1) {
        report({
          type: 'SEQUENCE_GAP',
          message: `Sequence jumps from ${previous.seq} to ${record.seq}: ${
            record.seq - previous.seq - 1
          } record(s) are missing from the chain`,
          expected: String(previous.seq + 1),
          actual: String(record.seq),
        });
      }
      if (record.prevHash !== previous.recordHash) {
        report({
          type: 'LINK_MISMATCH',
          message: 'Record does not link to its predecessor: history was spliced or reordered',
          expected: previous.recordHash,
          actual: record.prevHash,
        });
      }
    }

    // 2. Content: does the payload still match what was committed to?
    //    Redacted and archived fields verify against their retained leaf digests (ADR-0003),
    //    so legitimate policy operations produce no finding here - which is precisely the
    //    "no false positive for archived records" requirement (B2).
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: record.leaves,
      salts: record.salts,
      payload: record.payload,
    });
    if (root !== record.payloadRoot) {
      report({
        type: 'PAYLOAD_ROOT_MISMATCH',
        message: 'Payload does not match its committed Merkle root: a field value was altered',
        expected: record.payloadRoot,
        actual: root,
        paths: mismatchedPaths,
      });
    }

    // 3. Self-consistency: does the stored digest match the record's own hashed fields?
    const recomputedHash = computeRecordHash(coreOf(record));
    if (recomputedHash !== record.recordHash) {
      report({
        type: 'CONTENT_HASH_MISMATCH',
        message: 'Stored record hash does not match a recomputation of the record contents',
        expected: recomputedHash,
        actual: record.recordHash,
      });
    }

    if (options.stopAtFirstViolation && violations.length > 0) break;
    previous = record;
  }

  const [firstViolation, ...rest] = violations;

  return {
    intact: violations.length === 0,
    verifiedAt: new Date().toISOString(),
    recordsChecked,
    range: { fromSeq, toSeq },
    chainHead,
    firstViolation: firstViolation ?? null,
    furtherViolations: rest.slice(0, MAX_REPORTED_VIOLATIONS),
    totalViolations: violations.length,
    durationMs: Date.now() - startedAt,
  };
}
