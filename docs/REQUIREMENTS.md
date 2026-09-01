# Requirement Analysis & Normalization

This document is the bridge between the prose brief and the code. Every implemented
behaviour traces back to a numbered requirement here; every ambiguity I found is listed
with the assumption I made and how to reverse it.

## 1. Restating the problem in engineering terms

> Record an append-only history of events and guarantee that past records cannot be
> modified or deleted without detection.

Two claims are being made, and they are different:

| Claim | What it actually requires |
|---|---|
| **Append-only** | The *service* exposes no mutate/delete path. This is an API-surface property, enforceable by us. |
| **Tamper-evident** | Anyone with the data can *detect* out-of-band modification (someone with a SQLite shell). This is a cryptographic property. |

Note what is explicitly **not** claimed: tamper-*proof*. A privileged attacker with write
access to the datastore can always destroy data. What a hash chain buys is that they
cannot do so *silently* — any edit, deletion, or reordering of history invalidates the
chain from that point forward. Section 5 of `docs/ARCHITECTURE.md` states the exact
threat model, including the attack this design does **not** stop.

## 2. Normalized functional requirements

### Scenario A — Core service

| ID | Requirement | Verified by |
|---|---|---|
| A1 | `POST /audit/events` accepts `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, optional `timestamp`. | `tests/integration/write-api.test.ts` |
| A2 | No update or delete operation is exposed on an audit record. | `tests/integration/append-only.test.ts` |
| A3 | Query by any combination of `actorId`, `resourceType`, `resourceId`, `eventType`, `from`/`to`. | `tests/integration/query-api.test.ts` |
| A4 | Query results are paginated and stable under concurrent writes. | `tests/integration/query-api.test.ts` |
| A5 | Each record stores a hash of its own content and of the preceding record. | `tests/unit/chain.test.ts` |
| A6 | The first record links to a defined genesis value. | `tests/unit/chain.test.ts` |
| A7 | `GET /audit/verify` walks the chain and reports intactness. | `tests/integration/verify-api.test.ts` |
| A8 | On break: report the first inconsistent record and the violation type. | `tests/integration/tamper.test.ts` |

### Scenario B — Retention and redaction

| ID | Requirement | Verified by |
|---|---|---|
| B1 | Records older than a configurable window are archivable / soft-deletable. | `tests/integration/retention.test.ts` |
| B2 | Verification handles archived records correctly — **no false positive break**. | `tests/integration/retention.test.ts` |
| B3 | Sensitive `payload` fields are redactable without breaking the chain. | `tests/integration/redaction.test.ts` |
| B4 | Export all records for a `resourceId` or `actorId` as a self-contained, independently verifiable bundle. | `tests/integration/export.test.ts` |

### Scenario C — Ambiguous compliance requirement

Handled in full in `docs/SCENARIO_C.md`: the clarification process, the ambiguities, the
assumptions, the resulting design, and an explicit scope boundary for what I did not build.

| ID | Requirement (post-clarification) | Verified by |
|---|---|---|
| C1 | Regulator-facing read model over access events to client account data. | `tests/integration/compliance-report.test.ts` |
| C2 | The report is itself scoped, authenticated, and audited (reading it emits an audit event). | `tests/integration/compliance-report.test.ts` |

### Cross-cutting

| ID | Requirement |
|---|---|
| X1 | Authentication on every endpoint; least-privilege roles (`writer`/`reader`/`auditor`/`admin`). |
| X2 | Input validation at the boundary with explicit size limits (a hash chain is a durable, unbounded write surface). |
| X3 | Structured logging that never logs a payload body. |
| X4 | Deterministic, reproducible hashing across processes and machines. |

## 3. Ambiguities found, and how I resolved them

The brief is deliberately loose in several places. Each of these was a decision, not a
default.

### 3.1 Caller-supplied vs. server-assigned timestamp
The brief says "caller-supplied or server-assigned; **document your choice**".

**Decision: both, stored separately.** `occurredAt` is caller-supplied (defaulting to
server time when absent) and `recordedAt` is always server-assigned and non-negotiable.
Both are covered by the record hash.

*Why:* the two answer different questions. A domain event genuinely happened at a time the
caller knows and the server does not (batched/offline producers). But if the caller owns
the only timestamp, a malicious client can backdate an event into the middle of settled
history and the audit trail loses its evidentiary value. Ordering and retention therefore
key off `recordedAt`, while investigators can still see the claimed `occurredAt`.
Caller-supplied `occurredAt` is bounded by `MAX_CLOCK_SKEW_MS` so it cannot be absurd.

### 3.2 What "append-only" means for ordering
**Decision:** chain order is a monotonic server-assigned `seq`, in `recordedAt` order — not
`occurredAt` order. Out-of-order `occurredAt` values are legal and expected; they are a data
property, not a chain violation.

### 3.3 Single chain or one chain per tenant/resource?
**Decision: one global chain.** A single chain gives the strongest guarantee — no record can
be deleted wholesale without a visible gap. Per-resource chains would parallelize writes but
let an attacker drop an entire resource's chain undetected.
*Cost, stated plainly:* writes serialize on one chain tip, which caps throughput at roughly
single-node SQLite write speed. `docs/ARCHITECTURE.md` §7 describes the sharded-chain +
periodic-anchor design I would move to if that ceiling were reached.

### 3.4 "Archivable or soft-deletable" — which, and what survives?
**Decision:** archival removes *content* (payload plaintext), never *structure*. The record's
hash inputs remain fully re-derivable after archival, so verification stays purely
cryptographic and B2's "no false positive" requirement is met without special-casing the
verifier's trust model. See ADR-0004.

### 3.5 Redaction — how much is redactable?
**Decision:** individual `payload` fields only. Identity fields (`eventType`, `actorId`,
`resourceType`, `resourceId`, timestamps) are **not** redactable — they are the audit trail
itself. If GDPR erasure demands an `actorId` disappear, the answer is pseudonymisation at
write time, not redaction after the fact. Documented as a limitation, not hidden.

### 3.6 "Regulators need to audit access to client account data"
Five distinct ambiguities. Fully worked in `docs/SCENARIO_C.md`.

## 4. Explicit non-goals

Scoped out deliberately, with reasoning in `docs/ENGINEERING_SUMMARY.md` §5:

- Distributed consensus / multi-writer clustering.
- External anchoring (publishing periodic chain roots to an independent witness). Designed
  for in ADR-0002, not implemented — it is the single highest-value follow-up.
- Signed records (per-writer asymmetric signatures for non-repudiation).
- A UI. The brief states the APIs are the deliverable.
