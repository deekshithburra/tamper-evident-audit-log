/**
 * Application service: the only place that knows how a write becomes a chain link.
 *
 * Keeping this free of Express types means the exact same code path is exercised by unit
 * tests, HTTP integration tests, and any future transport (a queue consumer, a gRPC surface).
 */

import { randomUUID } from 'node:crypto';
import { canonicalize } from '../domain/canonical.js';
import { commitPayload, type Leaf } from '../domain/commitments.js';
import { DOMAIN, tagged } from '../domain/hash.js';
import { AppError } from '../domain/errors.js';
import {
  GENESIS_HASH,
  HASH_ALGORITHM,
  computeRecordHash,
  type RedactionMark,
  type StoredRecord,
} from '../domain/record.js';
import type { AuditRepository, Page, QueryFilters } from '../storage/repository.js';
import { verifyChain, type VerificationReport } from './verification.js';
import type { Config } from '../config.js';

/** Event types the service itself emits. They are ordinary records in the same chain. */
export const SYSTEM_EVENT_TYPES = {
  redaction: 'PAYLOAD_REDACTED',
  retention: 'RETENTION_POLICY_APPLIED',
  report: 'COMPLIANCE_REPORT_GENERATED',
  export: 'RECORDS_EXPORTED',
} as const;

export interface WriteEventInput {
  eventType: string;
  actorId: string;
  resourceType: string;
  resourceId: string;
  payload: Record<string, unknown>;
  /** Caller-supplied time the event occurred. Defaults to server time when omitted. */
  timestamp?: string;
}

export interface RedactionRequest {
  eventId: string;
  paths: string[];
  reason: string;
  /** Principal performing the redaction, recorded in the chain. */
  requestedBy: string;
}

export interface ExportBundle {
  bundleVersion: string;
  generatedAt: string;
  subject: { type: 'resource' | 'actor'; resourceType?: string; id: string };
  algorithm: string;
  genesisHash: string;
  /** Chain context: what the first exported record must link to, and where it sat globally. */
  chainContext: {
    firstRecordPrevHash: string;
    /** seq of every exported record, so a recipient sees this is a filtered slice, not a chain. */
    exportedSeqs: number[];
    globalChainHead: { seq: number; recordHash: string };
  };
  records: StoredRecord[];
  /** Digest over the bundle contents, so the bundle itself is tamper-evident in transit. */
  bundleHash: string;
}

export class AuditService {
  constructor(
    private readonly repo: AuditRepository,
    private readonly config: Config,
    private readonly now: () => Date = () => new Date(),
  ) {}

  // ---------------------------------------------------------------- write path

  append(input: WriteEventInput): StoredRecord {
    const recordedAt = this.now().toISOString();
    const occurredAt = this.resolveOccurredAt(input.timestamp, recordedAt);

    // Commitment is computed outside the transaction: it is CPU-bound and involves no shared
    // state, so there is no reason to hold the database write lock while doing it.
    const commitment = commitPayload(input.payload);

    return this.repo.appendAtomically((tip) => {
      const core = {
        seq: tip.seq + 1,
        eventId: randomUUID(),
        eventType: input.eventType,
        actorId: input.actorId,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        occurredAt,
        recordedAt,
        payloadRoot: commitment.root,
        prevHash: tip.recordHash,
        alg: HASH_ALGORITHM,
      };
      return {
        ...core,
        recordHash: computeRecordHash(core),
        leaves: commitment.leaves,
        salts: commitment.salts,
        payload: input.payload,
      };
    });
  }

  /**
   * Timestamp policy (REQUIREMENTS.md 3.1).
   *
   * `occurredAt` is the caller's claim and is bounded by configured clock skew; `recordedAt` is
   * the server's fact and is never caller-controlled. Without the bound, a client could backdate
   * an event into settled history - the record would still be chain-valid (it is appended at the
   * head) but the *narrative* the log tells would be false, which is the same harm by another route.
   */
  private resolveOccurredAt(supplied: string | undefined, recordedAt: string): string {
    if (supplied === undefined) return recordedAt;

    const occurred = new Date(supplied);
    if (Number.isNaN(occurred.getTime())) {
      throw AppError.validation('timestamp must be a valid ISO-8601 date-time');
    }
    const skew = occurred.getTime() - new Date(recordedAt).getTime();
    if (skew > this.config.maxClockSkewMs) {
      throw AppError.validation(
        `timestamp is ${Math.round(skew / 1000)}s in the future, beyond the permitted clock skew`,
      );
    }
    if (-skew > this.config.maxClockSkewMs) {
      throw AppError.validation(
        `timestamp is ${Math.round(-skew / 1000)}s in the past, beyond the permitted clock skew. ` +
          'Backdating an event past this bound is refused; submit it with the current time and ' +
          'record the original time inside the payload.',
      );
    }
    return occurred.toISOString();
  }

  // ---------------------------------------------------------------- read path

  getByEventId(eventId: string): StoredRecord {
    const record = this.repo.getByEventId(eventId);
    if (record === null) throw AppError.notFound(`No audit record with eventId "${eventId}"`);
    return record;
  }

  query(filters: QueryFilters, limit?: number, cursor?: string): Page<StoredRecord> {
    const size = Math.min(limit ?? this.config.defaultPageSize, this.config.maxPageSize);
    const parsedCursor = cursor === undefined ? undefined : Number(cursor);
    if (parsedCursor !== undefined && (!Number.isInteger(parsedCursor) || parsedCursor < 0)) {
      throw AppError.validation('cursor must be a non-negative integer returned by a prior page');
    }
    return this.repo.query(filters, size, parsedCursor);
  }

  // ---------------------------------------------------------------- verification

  verify(options: { fromSeq?: number } = {}): VerificationReport {
    const fromSeq = options.fromSeq ?? 1;
    if (fromSeq === 1) return verifyChain(this.repo.scan(1));

    // Verifying a suffix requires the predecessor's digest as the expected anchor, otherwise
    // the first record of the slice would be misreported as a genesis violation.
    const anchor = this.repo.getBySeq(fromSeq - 1);
    return verifyChain(this.repo.scan(fromSeq), {
      expectedFirstPrevHash: anchor === null ? GENESIS_HASH : anchor.recordHash,
    });
  }

  // ---------------------------------------------------------------- retention (Scenario B)

  /**
   * Archive records older than the retention window.
   *
   * Archival destroys payload plaintext and salts and leaves the entire hash skeleton intact,
   * so `recordHash` stays recomputable and verification needs no exception for archived
   * records (ADR-0004). The retention run is itself appended to the chain.
   */
  applyRetention(options: { windowDays?: number; limit?: number; appliedBy: string }): {
    archivedCount: number;
    archivedSeqs: number[];
    cutoff: string;
  } {
    const windowDays = options.windowDays ?? this.config.retentionWindowDays;
    if (!Number.isFinite(windowDays) || windowDays < 0) {
      throw AppError.validation('windowDays must be a non-negative number');
    }
    const cutoff = new Date(this.now().getTime() - windowDays * 86_400_000).toISOString();
    const candidates = this.repo.findArchivable(cutoff, options.limit ?? 1000);

    const archivedSeqs = this.repo.transaction(() => {
      const seqs: number[] = [];
      for (const record of candidates) {
        this.repo.updateContent(record.seq, {
          payload: null,
          salts: {},
          redactions: record.redactions,
          lifecycleState: 'archived',
          archivedAt: this.now().toISOString(),
        });
        seqs.push(record.seq);
      }
      return seqs;
    });

    if (archivedSeqs.length > 0) {
      this.append({
        eventType: SYSTEM_EVENT_TYPES.retention,
        actorId: options.appliedBy,
        resourceType: 'audit_log',
        resourceId: 'retention',
        payload: {
          cutoff,
          windowDays,
          archivedCount: archivedSeqs.length,
          firstSeq: archivedSeqs[0],
          lastSeq: archivedSeqs[archivedSeqs.length - 1],
        },
      });
    }

    return { archivedCount: archivedSeqs.length, archivedSeqs, cutoff };
  }

  // ---------------------------------------------------------------- redaction (Scenario B)

  /**
   * Redact payload fields without breaking the chain.
   *
   * Deletes the value *and its salt*, keeping the leaf digest. Deleting the salt is what makes
   * the erasure irreversible: without it a 9-digit account number behind an unsalted hash is
   * seconds of brute force away from being recovered from the "redacted" record (ADR-0003).
   */
  redact(request: RedactionRequest): StoredRecord {
    if (request.paths.length === 0) {
      throw AppError.validation('At least one payload path must be specified for redaction');
    }
    if (request.reason.trim().length < 3) {
      throw AppError.validation('A redaction reason is required and is recorded in the chain');
    }

    return this.repo.transaction(() => {
      const record = this.getByEventId(request.eventId);
      if (record.lifecycleState === 'archived' || record.payload === null) {
        throw AppError.conflict(
          'Record is archived: its payload has already been destroyed, so there is nothing to redact',
        );
      }

      const knownPaths = new Set(record.leaves.map((leaf: Leaf) => leaf.path));
      const unknown = request.paths.filter((path) => !knownPaths.has(path));
      if (unknown.length > 0) {
        throw AppError.validation(
          `Unknown payload path(s): ${unknown.join(', ')}. Valid paths for this record: ${[
            ...knownPaths,
          ].join(', ')}`,
        );
      }

      const alreadyRedacted = new Set(record.redactions.map((mark) => mark.path));
      const toRedact = request.paths.filter((path) => !alreadyRedacted.has(path));

      const payload = structuredClone(record.payload) as Record<string, unknown>;
      const salts = { ...record.salts };
      for (const path of toRedact) {
        deleteAtPath(payload, path);
        delete salts[path];
      }

      const redactedAt = this.now().toISOString();
      const marks: RedactionMark[] = [
        ...record.redactions,
        ...toRedact.map((path) => ({
          path,
          redactedAt,
          redactedBy: request.requestedBy,
          reason: request.reason,
        })),
      ];

      const updated = this.repo.updateContent(record.seq, {
        payload,
        salts,
        redactions: marks,
        lifecycleState: record.lifecycleState,
        archivedAt: record.archivedAt,
      });

      // The log records its own erasures: what was removed, by whom and why survives even
      // though the values do not.
      this.append({
        eventType: SYSTEM_EVENT_TYPES.redaction,
        actorId: request.requestedBy,
        resourceType: 'audit_record',
        resourceId: record.eventId,
        payload: {
          targetEventId: record.eventId,
          targetSeq: record.seq,
          paths: toRedact,
          reason: request.reason,
          alreadyRedacted: request.paths.filter((path) => alreadyRedacted.has(path)),
        },
      });

      return updated;
    });
  }

  // ---------------------------------------------------------------- export (Scenario B)

  /**
   * Export every record for one resource or actor as a self-contained bundle.
   *
   * Honest framing, stated in the bundle itself: this is a *filtered slice*, not a contiguous
   * chain, so a recipient cannot verify link-to-link continuity across it. What they can verify
   * offline, with no access to this service, is that each record's own hash matches its
   * contents and payload commitments, that the sequence numbers and prevHash values are exactly
   * as exported, and that the bundle has not been altered in transit. Proving *completeness* of
   * a filtered slice needs the full chain or an inclusion proof against a published head - the
   * global head is included so a recipient can demand exactly that.
   */
  exportBundle(subject: { actorId?: string; resourceType?: string; resourceId?: string }): ExportBundle {
    const isResource = subject.resourceId !== undefined;
    if (!isResource && subject.actorId === undefined) {
      throw AppError.validation('Specify either actorId, or resourceId (with optional resourceType)');
    }

    const filters: QueryFilters = { includeArchived: true };
    if (subject.actorId !== undefined) filters.actorId = subject.actorId;
    if (subject.resourceType !== undefined) filters.resourceType = subject.resourceType;
    if (subject.resourceId !== undefined) filters.resourceId = subject.resourceId;

    const records: StoredRecord[] = [];
    let cursor: string | undefined;
    do {
      const page = this.repo.query(filters, this.config.maxPageSize, cursor === undefined ? undefined : Number(cursor));
      records.push(...page.items);
      cursor = page.nextCursor ?? undefined;
    } while (cursor !== undefined);

    const tip = this.repo.tip();
    const first = records[0];
    const bundle: Omit<ExportBundle, 'bundleHash'> = {
      bundleVersion: 'audit-bundle-v1',
      generatedAt: this.now().toISOString(),
      subject: isResource
        ? {
            type: 'resource',
            ...(subject.resourceType === undefined ? {} : { resourceType: subject.resourceType }),
            id: subject.resourceId as string,
          }
        : { type: 'actor', id: subject.actorId as string },
      algorithm: HASH_ALGORITHM,
      genesisHash: GENESIS_HASH,
      chainContext: {
        firstRecordPrevHash: first?.prevHash ?? GENESIS_HASH,
        exportedSeqs: records.map((record) => record.seq),
        globalChainHead: { seq: tip.seq, recordHash: tip.recordHash },
      },
      records,
    };

    return { ...bundle, bundleHash: computeBundleHash(bundle) };
  }

  // ---------------------------------------------------------------- compliance (Scenario C)

  tip() {
    return this.repo.tip();
  }

  count(): number {
    return this.repo.count();
  }
}

/** Remove a value at an escaped leaf path, pruning nothing else. */
function deleteAtPath(target: Record<string, unknown>, path: string): void {
  const segments = path.split('.').map((segment) => segment.replace(/~1/g, '.').replace(/~0/g, '~'));
  let cursor: unknown = target;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const segment = segments[i] as string;
    if (cursor === null || typeof cursor !== 'object') return;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  const last = segments[segments.length - 1] as string;
  if (cursor !== null && typeof cursor === 'object') {
    if (Array.isArray(cursor)) {
      // Keep the array's length: removing an element would shift every later index and
      // invalidate the sibling leaf paths, which would look like tampering.
      (cursor as unknown[])[Number(last)] = null;
    } else {
      delete (cursor as Record<string, unknown>)[last];
    }
  }
}

/**
 * Digest over the bundle, so alteration in transit is detectable independently of the chain.
 * It commits to the ordered record hashes rather than to the serialized records, so a
 * recipient reproduces it from data they can also verify record-by-record.
 */
export function computeBundleHash(bundle: Omit<ExportBundle, 'bundleHash'>): string {
  return tagged(
    DOMAIN.bundle,
    bundle.bundleVersion,
    bundle.generatedAt,
    canonicalize(bundle.records.map((record) => record.recordHash)),
    canonicalize(bundle.chainContext),
  );
}
