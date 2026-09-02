# Final Engineering Summary

## 1. What was built

A tamper-evident, append-only audit log service. Node 20+, TypeScript (strict), Express,
SQLite. ~6,000 lines across source and tests; 230 tests; 96.8% statement coverage; full
suite runs in about four seconds.

- **Scenario A** - write and query APIs with filtering and stable pagination; SHA-256 hash
  chain; `GET /audit/verify` reporting intactness, the first inconsistency, and the *type* of
  violation.
- **Scenario B** - retention/archival that provably produces no false chain break; structured
  redaction that erases payload fields while leaving `recordHash` byte-identical; verifiable
  bulk export with a standalone offline verifier.
- **Scenario C** - a regulator-facing client-data access report, built against a clarified
  requirement with its assumptions and scope boundary written down.

## 2. Plan and rationale

The order of work was forced by one observation made before any code was written: Scenario
B's redaction requirement constrains Scenario A's storage format. Hashing the payload as a
single blob is simpler, passes every Scenario A test, and makes redaction impossible without
a migration. So field-level commitments were designed in from the first commit.

From there the critical path was `canonical serialization -> hashing -> record hash ->
storage -> verification`, with the tamper suite written before retention and redaction so
that both had a regression gate to satisfy. [TASK_PLAN.md](TASK_PLAN.md) records the
decomposition and the two places the plan changed under contact with the code.

## 3. Key decisions

| Decision | Why | Recorded in |
|---|---|---|
| SHA-256 over explicitly canonical JSON | Reproducibility across runtimes is a correctness requirement; a false tamper report destroys trust in true ones | ADR-0001 |
| `prevHash` inside the hash | Makes it a chain rather than a list of digests: altering record *n* invalidates all after it | ADR-0001 |
| Append-only at four layers | API, repository, DB triggers, cryptography. The first three prevent accidents; the fourth catches intent | ADR-0002 |
| Salted per-field Merkle commitments | The only scheme that satisfies erasure and tamper-evidence simultaneously | ADR-0003 |
| Destroy the salt with the value | Without it, low-entropy fields are recoverable from the retained leaf by brute force | ADR-0003 |
| Archival = content-only, skeleton retained | Verification needs no exception, so the archived flag cannot become a bypass | ADR-0004 |
| `BEGIN IMMEDIATE` on append | Takes the write lock before reading the chain tip, closing the fork race | ADR-0005 |
| Both timestamps, caller's bounded | Domain time and system time answer different questions; only one can be trusted | REQUIREMENTS §3.1 |
| Keyset pagination | Offset pages skip or repeat under concurrent writes | ARCHITECTURE §8 |
| `writer` cannot read | A compromised event producer must not be able to read the history it feeds | ARCHITECTURE §6 |
| Credentials expire, stage and revoke; checked per request | A key validated only at boot keeps working until the next deploy | ADR-0006 |
| Object-level scope enforced in the service layer | Role checks alone let any reader walk the whole log by event id (BOLA) | ADR-0006 |
| Out-of-scope record returns 404, not 403 | A 403 confirms the id exists, turning the API into an existence oracle | ADR-0006 |
| Rate limits per credential, in three cost classes | Verify/export/report are O(n); no write budget would stop a caller looping them | ADR-0006 |

## 4. Risks and trade-offs

| Risk | Severity | Mitigation / status |
|---|---|---|
| **Full-chain rewrite by an attacker with total store access** | High | Not mitigated in code. Requires external anchoring of the chain head. Designed in ADR-0002, deliberately out of scope; the honest boundary of the guarantee |
| **Tail truncation** | High | Same root cause, same fix. Asserted as a known limitation in the tamper suite rather than glossed over |
| Single-writer throughput ceiling | Medium | Accepted for a prototype; scaling path in ARCHITECTURE §7. Reasoned, not benchmarked |
| O(n) verification on large chains | Medium | Checkpointing designed, not built. `fromSeq` allows suffix verification today |
| API keys as bearer secrets | Medium | Prototype-grade and labelled: credentials now expire, stage, revoke and carry object-level scope, but they are still bearer tokens, not proof-of-possession. Production wants mTLS/OIDC; `CredentialStore` is the seam |
| Rate limiter state is per-instance | Low | Behind N replicas the effective limit is N x. Production wants a shared counter or gateway; `RateLimiter` is a one-method interface |
| Scope is static configuration | Low | A real deployment binds it to identity-provider claims rather than an environment variable |
| Retained leaf digests are not independently re-derivable for redacted fields | Low | Inherent to erasure. They remain bound into the root and chain, so they cannot be altered undetected |
| Payload *shape* survives redaction | Low | Usually desirable in audit. Redact the parent path if a field name is itself sensitive |
| SQLite in production | Low | Behind a repository interface; Postgres is a one-file change |

## 5. Assumptions

1. Producing applications are trusted to report events truthfully. This service guarantees
   that what it recorded cannot be altered - not that what it was told was true. Per-writer
   signatures would narrow this and are not implemented.
2. One logical tenant. Multi-tenancy would need either scoped chains (weakening the deletion
   guarantee) or tenant-scoped access control over one chain.
3. Payloads are bounded and structured (64 KB, 512 leaves, depth 12). An audit log is a
   permanent write surface and must bound its input.
4. Wall-clock time is approximately correct on the server; `recordedAt` ordering depends on it.
5. Scenario C's assumptions are separately enumerated in [SCENARIO_C.md](SCENARIO_C.md) §4.

## 6. Limitations

- No external anchoring, no per-record signatures, no distributed operation.
- Retention archives but never reclaims storage; true cold-storage removal would need a
  signed checkpoint covering the removed range.
- Verification is synchronous and blocks the event loop for the duration; on a large chain
  it belongs in a worker.
- No load or multi-process concurrency testing ([TESTING.md](TESTING.md)). Crash durability
  *is* now covered by a SIGKILL-based suite, but only for process death - not host power loss
  with the page cache in flight.
- The compliance report can only report what it was told; an application that reads client
  data without emitting an event is invisible to it, and that is a limitation of the
  approach rather than of this implementation.

## 7. If I had another week

In priority order, and the order matters:

1. **External anchoring.** It closes the two High risks above, and everything else is
   secondary to it. Nothing else changes what the system can actually guarantee.
2. **Postgres plus a load benchmark.** ARCHITECTURE §7's scaling claims are currently
   reasoned rather than measured, which is a gap I would rather close than argue.
3. **Signed checkpoints**, giving O(1) incremental verification and making cold-storage
   removal explainable.
4. **Per-writer signatures**, narrowing assumption 1 from "trusted producers" to
   "authenticated producers with non-repudiation".
5. **A generative fuzzer** for the canonical serializer, replacing hand-rolled shuffles.
6. **Shared-store rate limiting and IdP-bound scope**, replacing the two deployment-shaped
   compromises in ADR-0006.

## 8. What I would want to be asked about

The parts I find most defensible are the ones where the obvious implementation is subtly
wrong: archival as content-only rather than row deletion, destroying the salt rather than
just the value, `BEGIN IMMEDIATE` rather than a plain transaction, and detection living in
the Merkle root rather than in a returned list. Each of those is a place where working code
and correct code diverge, and each is documented with the alternative I rejected.

The part I would push back on if a reviewer called it complete is the threat model. This
system makes tampering *detectable*, not *impossible*, and against an attacker with full
store access it is detectable only if a head is anchored somewhere they do not control.
That is stated in the architecture, asserted in the tests, and would be my first
recommendation in a production review.
