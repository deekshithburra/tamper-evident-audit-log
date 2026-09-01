/**
 * Append-only persistence (ADR-0002 layer 2, ADR-0005).
 *
 * This class has no general-purpose update or delete method, by construction. The only
 * mutations it offers are the two policy operations the brief requires - archive and redact -
 * and both are restricted to columns that are not hash inputs.
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { PRAGMAS, SCHEMA_SQL, SCHEMA_VERSION } from './schema.js';
import type { Leaf } from '../domain/commitments.js';
import { GENESIS_HASH, type LifecycleState, type RedactionMark, type StoredRecord } from '../domain/record.js';

export interface AppendInput {
  eventId: string;
  eventType: string;
  actorId: string;
  resourceType: string;
  resourceId: string;
  occurredAt: string;
  recordedAt: string;
  payloadRoot: string;
  prevHash: string;
  alg: string;
  recordHash: string;
  leaves: Leaf[];
  salts: Record<string, string>;
  payload: Record<string, unknown>;
}

export interface QueryFilters {
  actorId?: string;
  resourceType?: string;
  resourceId?: string;
  eventType?: string;
  /** Inclusive lower bound on `recordedAt`. */
  from?: string;
  /** Exclusive upper bound on `recordedAt`. */
  to?: string;
  includeArchived?: boolean;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

interface Row {
  seq: number;
  event_id: string;
  event_type: string;
  actor_id: string;
  resource_type: string;
  resource_id: string;
  occurred_at: string;
  recorded_at: string;
  payload_root: string;
  prev_hash: string;
  alg: string;
  record_hash: string;
  leaves_json: string;
  payload_json: string | null;
  field_salts_json: string;
  redactions_json: string;
  lifecycle_state: LifecycleState;
  archived_at: string | null;
}

function toRecord(row: Row): StoredRecord {
  return {
    seq: row.seq,
    eventId: row.event_id,
    eventType: row.event_type,
    actorId: row.actor_id,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    occurredAt: row.occurred_at,
    recordedAt: row.recorded_at,
    payloadRoot: row.payload_root,
    prevHash: row.prev_hash,
    alg: row.alg,
    recordHash: row.record_hash,
    leaves: JSON.parse(row.leaves_json) as Leaf[],
    payload: row.payload_json === null ? null : (JSON.parse(row.payload_json) as Record<string, unknown>),
    salts: JSON.parse(row.field_salts_json) as Record<string, string>,
    redactions: JSON.parse(row.redactions_json) as RedactionMark[],
    lifecycleState: row.lifecycle_state,
    archivedAt: row.archived_at,
  };
}

export interface ChainTip {
  seq: number;
  recordHash: string;
}

export class AuditRepository {
  private readonly db: Database.Database;

  constructor(databasePath: string) {
    if (databasePath !== ':memory:') mkdirSync(dirname(databasePath), { recursive: true });
    this.db = new Database(databasePath);
    for (const pragma of PRAGMAS) this.db.exec(pragma);
    this.db.exec(SCHEMA_SQL);
    this.db
      .prepare('INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)')
      .run('schema_version', String(SCHEMA_VERSION));
  }

  close(): void {
    this.db.close();
  }

  /** Escape hatch used exclusively by tests that simulate an attacker with database access. */
  unsafeRawHandle(): Database.Database {
    return this.db;
  }

  tip(): ChainTip {
    const row = this.db
      .prepare('SELECT seq, record_hash FROM audit_events ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; record_hash: string } | undefined;
    return row === undefined
      ? { seq: 0, recordHash: GENESIS_HASH }
      : { seq: row.seq, recordHash: row.record_hash };
  }

  count(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM audit_events').get() as { n: number }).n;
  }

  /**
   * Append inside a single IMMEDIATE transaction.
   *
   * `build` receives the chain tip and returns the record to insert. Reading the tip and
   * inserting the successor happen under the same write lock, which is what makes concurrent
   * appends serialize instead of forking the chain (ADR-0005). The lock is taken *before* the
   * read - a deferred transaction would read the tip without holding it, which is exactly the
   * race this design exists to close.
   */
  appendAtomically(build: (tip: ChainTip) => AppendInput): StoredRecord {
    const insert = this.db.prepare(`
      INSERT INTO audit_events (
        event_id, event_type, actor_id, resource_type, resource_id,
        occurred_at, recorded_at, payload_root, prev_hash, alg, record_hash,
        leaves_json, payload_json, field_salts_json
      ) VALUES (
        @eventId, @eventType, @actorId, @resourceType, @resourceId,
        @occurredAt, @recordedAt, @payloadRoot, @prevHash, @alg, @recordHash,
        @leavesJson, @payloadJson, @saltsJson
      )
    `);

    const transaction = this.db.transaction((): StoredRecord => {
      const input = build(this.tip());
      const result = insert.run({
        eventId: input.eventId,
        eventType: input.eventType,
        actorId: input.actorId,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        occurredAt: input.occurredAt,
        recordedAt: input.recordedAt,
        payloadRoot: input.payloadRoot,
        prevHash: input.prevHash,
        alg: input.alg,
        recordHash: input.recordHash,
        leavesJson: JSON.stringify(input.leaves),
        payloadJson: JSON.stringify(input.payload),
        saltsJson: JSON.stringify(input.salts),
      });
      return this.getBySeq(Number(result.lastInsertRowid)) as StoredRecord;
    });

    return transaction.immediate();
  }

  getBySeq(seq: number): StoredRecord | null {
    const row = this.db.prepare('SELECT * FROM audit_events WHERE seq = ?').get(seq) as
      | Row
      | undefined;
    return row === undefined ? null : toRecord(row);
  }

  getByEventId(eventId: string): StoredRecord | null {
    const row = this.db.prepare('SELECT * FROM audit_events WHERE event_id = ?').get(eventId) as
      | Row
      | undefined;
    return row === undefined ? null : toRecord(row);
  }

  /**
   * Keyset pagination on `seq`.
   *
   * Offset pagination would silently skip or repeat records when writes land between pages -
   * unacceptable when the consumer is a regulator reconciling a complete history. A cursor on
   * the monotonic chain position is stable by construction.
   */
  query(filters: QueryFilters, limit: number, cursor?: number): Page<StoredRecord> {
    const clauses: string[] = [];
    const params: Record<string, unknown> = {};

    if (filters.actorId !== undefined) {
      clauses.push('actor_id = @actorId');
      params.actorId = filters.actorId;
    }
    if (filters.resourceType !== undefined) {
      clauses.push('resource_type = @resourceType');
      params.resourceType = filters.resourceType;
    }
    if (filters.resourceId !== undefined) {
      clauses.push('resource_id = @resourceId');
      params.resourceId = filters.resourceId;
    }
    if (filters.eventType !== undefined) {
      clauses.push('event_type = @eventType');
      params.eventType = filters.eventType;
    }
    if (filters.from !== undefined) {
      clauses.push('recorded_at >= @from');
      params.from = filters.from;
    }
    if (filters.to !== undefined) {
      clauses.push('recorded_at < @to');
      params.to = filters.to;
    }
    if (filters.includeArchived !== true) {
      clauses.push("lifecycle_state = 'active'");
    }
    if (cursor !== undefined) {
      clauses.push('seq > @cursor');
      params.cursor = cursor;
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    // Fetch one extra row to determine whether a further page exists without a second query.
    const rows = this.db
      .prepare(`SELECT * FROM audit_events ${where} ORDER BY seq ASC LIMIT @limit`)
      .all({ ...params, limit: limit + 1 }) as Row[];

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    return {
      items: page.map(toRecord),
      nextCursor: hasMore ? String(page[page.length - 1]?.seq) : null,
    };
  }

  /** Streaming scan in chain order. Verification must never load the whole chain into memory. */
  *scan(fromSeq = 1, batchSize = 500): Generator<StoredRecord> {
    const statement = this.db.prepare(
      'SELECT * FROM audit_events WHERE seq >= ? ORDER BY seq ASC LIMIT ?',
    );
    let cursor = fromSeq;
    for (;;) {
      const rows = statement.all(cursor, batchSize) as Row[];
      if (rows.length === 0) return;
      for (const row of rows) yield toRecord(row);
      cursor = (rows[rows.length - 1] as Row).seq + 1;
    }
  }

  /**
   * Records eligible for archival: active, and recorded at or before the cutoff.
   *
   * The bound is inclusive deliberately. `recorded_at` has millisecond resolution, so with a
   * strict `<` any record written in the same millisecond the cutoff was computed is skipped -
   * leaving a trickle of records straddling every run boundary, and making a zero-day window
   * non-deterministic. Inclusive is both simpler to reason about and stable.
   */
  findArchivable(cutoffIso: string, limit: number): StoredRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM audit_events
         WHERE lifecycle_state = 'active' AND recorded_at <= ? ORDER BY seq ASC LIMIT ?`,
      )
      .all(cutoffIso, limit) as Row[];
    return rows.map(toRecord);
  }

  /**
   * Persist a policy mutation.
   *
   * Deliberately narrow: this is the *only* write path other than append, it names its five
   * mutable columns explicitly, and the schema triggers abort if it were ever widened to touch
   * a hashed column.
   */
  updateContent(
    seq: number,
    next: {
      payload: Record<string, unknown> | null;
      salts: Record<string, string>;
      redactions: RedactionMark[];
      lifecycleState: LifecycleState;
      archivedAt: string | null;
    },
  ): StoredRecord {
    this.db
      .prepare(
        `UPDATE audit_events
            SET payload_json     = @payloadJson,
                field_salts_json = @saltsJson,
                redactions_json  = @redactionsJson,
                lifecycle_state  = @lifecycleState,
                archived_at      = @archivedAt
          WHERE seq = @seq`,
      )
      .run({
        seq,
        payloadJson: next.payload === null ? null : JSON.stringify(next.payload),
        saltsJson: JSON.stringify(next.salts),
        redactionsJson: JSON.stringify(next.redactions),
        lifecycleState: next.lifecycleState,
        archivedAt: next.archivedAt,
      });
    return this.getBySeq(seq) as StoredRecord;
  }

  /** Run several operations under one write lock (used by redact-and-log-the-redaction). */
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }
}
