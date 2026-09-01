# Task Decomposition & Sequencing

How the brief was broken into executable units before any code was written, and the order
forced by real dependencies. Each task carries intent, constraints and acceptance criteria —
the same framing used to drive the AI assistance (see `docs/AI_USAGE_LOG.md`).

## Dependency graph

```
T1 canonical serialization ──┐
                             ├──> T3 chain primitives ──> T4 storage ──> T5 write API ──┐
T2 field commitments ────────┘                                                          │
                                                                                        ├──> T6 query API
                                                    T7 verification engine <────────────┘
                                                            │
                        ┌───────────────────────────────────┼──────────────────┐
                        v                                   v                  v
                 T8 retention/archival            T9 structured redaction   T10 export bundle
                        └───────────────┬───────────────────┘                  │
                                        v                                      v
                              T11 compliance report (Scenario C)     T12 standalone verifier CLI
                                        │
                                        v
                              T13 auth & hardening ──> T14 e2e tamper demo ──> T15 docs
```

**Critical path:** T1 → T3 → T4 → T7. Verification is the load-bearing feature; everything
else is either an input to it or a consumer of it, so it was built and tested first and the
tamper test (T14) was written before the retention and redaction work that had to keep
passing it.

## Tasks

| # | Task | Intent | Key constraint | Acceptance criteria |
|---|---|---|---|---|
| T1 | Canonical JSON | Byte-identical serialization anywhere | Deterministic across runtimes; reject non-representable values | Property test: 1k shuffled-key objects → identical bytes |
| T2 | Field commitments | Per-field salted hashing + Merkle root | Hiding commitment; salt destroyable | Same payload, different salts → different leaves, same-shape root recompute |
| T3 | Chain primitives | `recordHash`, `prevHash`, genesis | Pure functions, no I/O — must be testable and reusable by the offline verifier | Known-answer tests; one-bit change → different digest |
| T4 | Storage layer | Append-only persistence | Triggers block mutation of hash inputs | Trigger tests prove `UPDATE`/`DELETE` abort |
| T5 | Write API | `POST /audit/events` | Validation, size limits, timestamp policy | 201 + record; oversized/invalid → 400 |
| T6 | Query API | Filter + paginate | Keyset pagination stable under concurrent writes | Page-through equals full scan with interleaved writes |
| T7 | Verification | Walk chain, classify violations | Must distinguish violation *types*, not just pass/fail | Each violation type reproduced by a test that corrupts the DB directly |
| T8 | Retention | Archive past window | No false-positive break (B2) | Archive 50 records → chain still `intact` |
| T9 | Redaction | Erase field, keep chain | Salt destroyed with value | Redact → value gone, `recordHash` byte-identical, chain intact |
| T10 | Export | Self-contained verifiable bundle | Recipient verifies offline with no service access | CLI verifies bundle; mutated bundle fails |
| T11 | Compliance report | Scenario C | Report access is itself audited | Report emits `AUDIT_REPORT_GENERATED` |
| T12 | Verifier CLI | Independent verification | Shares only pure primitives with the server | Runs against exported JSON, no DB |
| T13 | Auth/hardening | Least privilege | Role per endpoint; timing-safe key compare | Role matrix test, 401/403 paths |
| T14 | E2E demo | Prove the whole claim | Real HTTP + real SQL tampering | `scripts/demo.sh` shows detection end to end |
| T15 | Docs | Reviewability | Trade-offs and limits stated | This directory |

## Where the plan changed during execution

Real decomposition survives contact with the code imperfectly; two things moved.

1. **T8 was originally "delete archived rows, teach the verifier to skip them".** Writing the
   T8 acceptance test made it obvious that this hands the attacker a bypass flag
   (ADR-0004). Redesigned mid-task to content-only archival, which also *deleted* the
   verifier special-case rather than adding one — a good sign the second design was right.
2. **T2 originally hashed the payload as one blob.** That is simpler and passes every
   Scenario A test, but makes T9 impossible without a rewrite. Field-level commitments were
   pulled forward into T2 once I traced the Scenario B dependency, rather than discovering
   it later. Cost: ~2h extra in T2; saved a storage-format migration in T9.
