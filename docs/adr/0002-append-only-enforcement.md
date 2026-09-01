# ADR-0002: Enforcing append-only at every layer

**Status:** Accepted · **Date:** 2026-08-30

## Context
"Append-only" enforced only by "we didn't write an UPDATE endpoint" is a convention, not a
control. Defence in depth is cheap here.

## Decision — four layers

1. **API surface.** No `PUT`/`PATCH`/`DELETE` route exists on `/audit/events/*`. Requests to
   those methods return `405` with an explanatory body rather than a bare `404`, so the
   constraint is discoverable rather than looking like a bug.
2. **Repository.** `AuditRepository` exposes `append`, reads, and the two *policy* mutations
   (archive, redact). It contains no general-purpose update or delete path.
3. **Database triggers.** SQLite `BEFORE UPDATE`/`BEFORE DELETE` triggers on `audit_events`
   `RAISE(ABORT)` on any change to an immutable column, and on any delete at all. Policy
   mutations are permitted to touch *only* `payload_json`, `field_salts_json`,
   `redactions_json`, `archived_at` and `lifecycle_state` — columns that are deliberately
   **not** hash inputs. A stray `UPDATE audit_events SET actor_id=...` from any code path,
   including a future maintainer's migration script, aborts.
4. **Cryptographic backstop.** If someone bypasses all of the above (direct file edit,
   triggers dropped), the hash chain still surfaces it at the next verification. This is the
   layer that actually satisfies the brief; the first three make accidents impossible and
   deliberate tampering require intent that is itself evidence.

## Consequences
- Policy operations must be surgical about which columns they touch, and the tests assert
  the triggers fire (`tests/integration/append-only.test.ts`).
- Triggers are SQLite-specific. On Postgres the same guarantee comes from column-level
  `REVOKE UPDATE` plus a `BEFORE` trigger; the repository interface is unchanged.

## Not implemented (deliberate, highest-value follow-up)
**External anchoring.** An attacker with write access to *both* records and triggers can
rewrite history from record *k* forward and recompute every subsequent hash — the chain
verifies clean. Detection requires an anchor the attacker does not control: publish the
chain head periodically to an append-only external witness (a second-party log, a
timestamping authority, object storage with an object-lock retention policy). Then
rewriting history requires forging anchors held elsewhere. This is a deployment/ops
concern more than a code concern, which is why it is scoped out of a 2–3 day prototype —
but it is the honest boundary of what this implementation guarantees, and it is stated in
`docs/ARCHITECTURE.md` §5 rather than buried here.
