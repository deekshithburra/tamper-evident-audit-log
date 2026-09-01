# ADR-0004: Retention as content-only archival

**Status:** Accepted · **Date:** 2026-08-31

## Context
Records past a configurable window must be archivable/soft-deletable, and the verifier must
not report a false break for records legitimately archived per policy.

## The trap in the obvious implementation
The intuitive approach is to delete archived rows and have the verifier "skip gaps that are
marked archived". That is a false economy: it makes the verifier trust a mutable
`archived` flag. An attacker deletes records 40–60, flags the gap as archived, and the
verifier waves it through. The soft-delete flag becomes the tamper vector.

## Decision
**Archival is redaction of every payload leaf, plus a lifecycle marker. The chain skeleton
is never removed.**

An archived record retains `seq`, `eventId`, identity fields, both timestamps,
`payloadRoot`, `prevHash`, `recordHash` and all leaf digests. Only payload plaintext and
salts are destroyed. Therefore:

- `recordHash` remains **fully recomputable from stored data** after archival. The verifier
  needs no special case, no exception list, and no trust in the `lifecycle_state` column.
  B2 is satisfied structurally rather than by a carve-out.
- A genuine deletion of an archived record still shows as a sequence gap and a chain break,
  because the skeleton was supposed to still be there.

`lifecycle_state` is reported in query results (`active` | `archived`) so consumers know why
a payload is absent, and archived records are excluded from default query results unless
`includeArchived=true` is passed — that is the "soft-delete" half of the requirement.

## Consequences
- Storage is not reclaimed proportionally to volume; roughly 250 bytes of skeleton per
  archived record persists indefinitely. Correct trade for an audit log: the guarantee is
  the product.
- Hard deletion (true storage reclamation, e.g. moving 7-year-old records to cold storage) is
  a separate operation not implemented here. It would require a signed checkpoint covering
  the removed range so the gap remains explainable and verifiable — noted as future work.
- Archival is driven explicitly via `POST /audit/retention/apply` (admin) rather than a
  background timer, so the prototype has no hidden scheduler mutating state under the tests.
  Production would run the same code path from a scheduled job.
