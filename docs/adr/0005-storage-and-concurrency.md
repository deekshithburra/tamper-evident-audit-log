# ADR-0005: Storage engine and write serialization

**Status:** Accepted · **Date:** 2026-08-30

## Context
Appending to a chain is a read-modify-write on shared state: read the tip, compute
`prevHash`, insert. Two concurrent writers that read the same tip produce two records
claiming the same predecessor — a forked chain, which the verifier correctly reports as
corruption. The race is the interesting engineering problem in the write path.

## Decision
- **SQLite via `better-sqlite3`**, WAL mode, `synchronous = FULL`, foreign keys on.
- Every append runs inside a `BEGIN IMMEDIATE` transaction, which takes the write lock
  *before* the tip is read. Concurrent appends serialize at the database rather than
  interleaving. `busy_timeout` is set so contenders wait instead of failing.
- `seq` is `INTEGER PRIMARY KEY` with a `UNIQUE` constraint on `prev_hash` — a forked chain
  is rejected by the database even if application logic were wrong. Cheap belt-and-braces on
  the one invariant that matters most.
- `synchronous = FULL` (not the WAL default `NORMAL`): an audit log that acknowledges a write
  it can lose on power failure is lying to its caller. The fsync cost is the point.

## Why not Postgres
Postgres is the production answer (concurrent readers, real roles, column-level `REVOKE`).
For a reviewable prototype SQLite gives a zero-setup, file-backed, fully transactional store
with the same isolation semantics for this access pattern. Storage sits behind
`AuditRepository`, so the port is a single file. The concurrency test
(`tests/integration/concurrency.test.ts`) asserts the invariant, not the engine.

## Consequences
- Single-writer throughput ceiling — accepted and quantified in `docs/REQUIREMENTS.md` §3.3.
- `DATABASE_PATH=":memory:"` gives tests an isolated database per suite with no fixture
  cleanup and no cross-test bleed.
