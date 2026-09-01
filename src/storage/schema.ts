/**
 * Schema and the database-level append-only controls (ADR-0002, layer 3).
 *
 * The triggers below are the part worth reading. They make immutability a property of the
 * data store rather than a property of our discipline: any UPDATE that touches a hashed
 * column, and any DELETE at all, aborts - including one issued by a future maintainer's
 * migration script, an ORM, or a hand-typed statement in a SQLite shell.
 *
 * The columns left mutable are exactly the ones outside `HASHED_FIELDS`, which is why
 * retention and redaction can operate without any possibility of breaking the chain.
 */

export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  -- Chain position. Server-assigned, monotonic, and part of the hashed core.
  seq              INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id         TEXT    NOT NULL UNIQUE,
  event_type       TEXT    NOT NULL,
  actor_id         TEXT    NOT NULL,
  resource_type    TEXT    NOT NULL,
  resource_id      TEXT    NOT NULL,
  occurred_at      TEXT    NOT NULL,
  recorded_at      TEXT    NOT NULL,
  payload_root     TEXT    NOT NULL,
  -- UNIQUE is the structural guarantee against a forked chain: two records cannot both
  -- claim the same predecessor even if the application logic were wrong (ADR-0005).
  prev_hash        TEXT    NOT NULL UNIQUE,
  alg              TEXT    NOT NULL,
  record_hash      TEXT    NOT NULL UNIQUE,
  -- Committed leaf digests. Not hashed directly, but covered by payload_root, so altering
  -- this column is detected by verification exactly like any other tamper.
  leaves_json      TEXT    NOT NULL,

  -- Mutable by policy operations only. None of these are hash inputs.
  payload_json     TEXT,
  field_salts_json TEXT    NOT NULL DEFAULT '{}',
  redactions_json  TEXT    NOT NULL DEFAULT '[]',
  lifecycle_state  TEXT    NOT NULL DEFAULT 'active'
                   CHECK (lifecycle_state IN ('active', 'archived')),
  archived_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_actor       ON audit_events (actor_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_resource    ON audit_events (resource_type, resource_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type        ON audit_events (event_type, seq);
CREATE INDEX IF NOT EXISTS idx_events_recorded_at ON audit_events (recorded_at, seq);

-- Layer 3 of append-only enforcement.
--
-- Any change to a column that participates in the hash chain is refused outright. Redaction
-- and archival need only payload_json, field_salts_json, redactions_json, lifecycle_state and
-- archived_at, so they pass; everything else aborts.
CREATE TRIGGER IF NOT EXISTS audit_events_immutable_update
BEFORE UPDATE ON audit_events
WHEN
  old.seq           <> new.seq
  OR old.event_id      <> new.event_id
  OR old.event_type    <> new.event_type
  OR old.actor_id      <> new.actor_id
  OR old.resource_type <> new.resource_type
  OR old.resource_id   <> new.resource_id
  OR old.occurred_at   <> new.occurred_at
  OR old.recorded_at   <> new.recorded_at
  OR old.payload_root  <> new.payload_root
  OR old.prev_hash     <> new.prev_hash
  OR old.alg           <> new.alg
  OR old.record_hash   <> new.record_hash
  OR old.leaves_json   <> new.leaves_json
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: hashed columns cannot be modified');
END;

-- Archival removes content, never the chain skeleton (ADR-0004). Nothing is ever deleted.
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: records cannot be deleted');
END;

-- A record may be archived, but never un-archived: lifecycle is a one-way transition, so an
-- operator cannot quietly restore a record they were required to archive.
CREATE TRIGGER IF NOT EXISTS audit_events_lifecycle_forward_only
BEFORE UPDATE OF lifecycle_state ON audit_events
WHEN old.lifecycle_state = 'archived' AND new.lifecycle_state <> 'archived'
BEGIN
  SELECT RAISE(ABORT, 'lifecycle_state cannot move back from archived to active');
END;
`;

export const PRAGMAS = [
  'PRAGMA journal_mode = WAL',
  // Durability over throughput: an audit log that acknowledges a write it can lose on power
  // failure is lying to its caller (ADR-0005).
  'PRAGMA synchronous = FULL',
  'PRAGMA foreign_keys = ON',
  'PRAGMA busy_timeout = 5000',
] as const;
