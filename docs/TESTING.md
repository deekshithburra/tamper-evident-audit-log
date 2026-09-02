# Testing: Approach, Coverage, and What Is Not Covered

230 tests, 19 files, 96.8% statement coverage, ~4s to run.
`npm test` · `npm run test:coverage` · `npm run test:report` · `npm run check`.

Captured run output and the full coverage table live in [TEST_REPORT.md](TEST_REPORT.md);
`npm run test:report` regenerates JUnit XML, structured JSON and an HTML coverage report into
`reports/`, which CI publishes as build artefacts. Coverage thresholds are enforced in
`vitest.config.ts`, so a regression fails the build rather than being noticed later.

## Approach

**Test the guarantee, not the implementation.** The claim this system makes is "past records
cannot be modified or deleted without detection". So the load-bearing tests bypass the API
entirely and edit SQLite directly. Tests that only exercise our own endpoints would prove
that we didn't write an update method - which is not the claim.

**Unit tests for the cryptography, integration tests for everything else.** The hashing
primitives are pure and deserve exhaustive property-style testing. Everything above them is
tested through real HTTP against a real database, because the interesting failures live in
the seams - validation, transactions, projections - not inside a single class. There are no
mocks of the repository or the service: mocking the thing under test would only assert that
the mock behaves as I imagined.

**Each test file maps to a requirement ID** from [REQUIREMENTS.md](REQUIREMENTS.md), so
coverage of the *specification* is visible, not just coverage of the lines.

## What each suite covers

| Suite | Tests | Covers |
|---|---|---|
| `unit/canonical` | 7 | Key-order independence (500 shuffles), `-0`, rejection of non-representable values, path reporting |
| `unit/commitments` | 17 | Flattening, path escaping, salt uniqueness, Merkle properties, leaf-count binding, redaction-safety, emptied containers |
| `unit/record` | 5 | Known-answer digest, sensitivity to every hashed field, insensitivity to lifecycle fields |
| `unit/config` | 5 | Defaults, key parsing, boot-time failure, refusal of dev keys in production |
| `integration/write-api` | 18 | Happy path, chain linking, timestamp policy, 8 validation cases, size limits |
| `integration/query-api` | 10 | Every filter, combinations, time ranges, pagination completeness and stability under concurrent writes |
| `integration/append-only` | 13 | 405s, trigger aborts per hashed column, delete refusal, forked-chain rejection |
| `integration/tamper` | 13 | Nine attack shapes, violation typing, suffix verification, availability after tamper |
| `integration/retention` | 11 | Archival, **no false break (B2)**, skeleton preservation, query visibility, idempotence, batching |
| `integration/redaction` | 12 | **Hash identical before/after**, salt destruction, selectivity, arrays, self-auditing, authorization |
| `integration/export` | 11 | Bundle contents, offline verification, four tampering attempts |
| `integration/compliance-report` | 12 | Scope, filtering, purpose findings, integrity evidence, self-auditing, archived inclusion |
| `integration/concurrency` | 3 | 100 concurrent writes stay unforked; interleaved read/write/verify; interleaved redaction |
| `integration/auth` | 32 | Full role matrix (24 cases), credential handling, headers, error hygiene |
| `unit/credentials` | 16 | Expiry, staging, revocation, rotation overlap, inventory, production guards |
| `integration/credential-lifecycle` | 10 | Per-request lifecycle enforcement, rotation headers, inventory |
| `integration/object-authorization` | 18 | **BOLA**: cross-tenant reads, existence-oracle behaviour, every route |
| `integration/rate-limit` | 12 | Budgets by cost class, headers, window rollover, credential isolation |
| `integration/crash-recovery` | 4 | SIGKILL mid-write: durability of acknowledged writes, no torn records |

## Tests that assert limits rather than capabilities

Two tests deliberately assert that something is **not** detected:

- *"detects a truncated tail only against an externally held head"* - deleting the newest
  records leaves an internally consistent chain. The test asserts `intact: true` and that
  the head moved, documenting the boundary in executable form.
- *"a filtered export cannot prove completeness"* - encoded in the verifier's own output.

Writing these felt uncomfortable, which is the point. A test suite that only demonstrates
strengths is a sales document; the boundary of a security claim is part of the claim.

## Defects the tests found

All three were fixed in the code, not the assertion:

1. **Injected payload field detected but not reflected in the root.** `recomputeRoot`
   reported an added field in `mismatchedPaths` while leaving the Merkle root unchanged - so
   the chain verifier, which compares roots, would have passed it. Detection now lives in the
   value the chain covers rather than in a side channel.
2. **Emptied containers read as tampering.** Redacting the last field of an object leaves
   `{}`, which the flattener commits as a leaf of its own, so a legitimate erasure looked
   like an injected field. Now recognised by its retained committed descendants.
3. **Retention boundary off-by-one.** A strict `recorded_at <` cutoff skipped records written
   in the same millisecond as the cutoff, leaving a trickle straddling every run boundary.

A fourth was an environment defect rather than a service one, and is worth recording because
it cost the most time: test servers bound dual-stack via `listen(0)`, so a request to
`127.0.0.1:<port>` could reach an **unrelated local process** holding that port on IPv4. It
presented as random 404s and ECONNRESETs across unrelated suites; the giveaway was a 401
whose body was another service's error envelope. Binding `127.0.0.1` explicitly and awaiting
the bind fixed it - confirmed over 15 consecutive clean full-suite runs before file
parallelism was restored. The lesson I'd keep: intermittent failures scattered across
unrelated tests are usually one shared-resource bug, not several unrelated ones.

## Crash simulation

The one test that checks a claim the rest of the suite only restates. Every other test runs
in-memory in a process that exits cleanly, which proves nothing about a power cut.
`crash-recovery.test.ts` spawns a real writer process, kills it with an uncatchable **SIGKILL**
mid-write, and reopens the file - asserting that every acknowledged write survived, that the
chain still verifies, that sequence numbers are contiguous, and that a new append links to the
head that survived.

The second property is the subtle one: a half-written record left behind would be reported by
the verifier as *tampering*, and a system that cries tamper after every unclean shutdown is one
nobody will believe when it matters. `npm run demo:crash` shows the same thing interactively.

Honest boundary: SIGKILL proves survival of a *process* crash. It does not simulate host power
loss with the OS page cache in flight - that needs a VM snapshot or a fault injector.
`synchronous = FULL` is what covers that case, and this test is what stops it being quietly
downgraded to `NORMAL` for a throughput win.

## What is not covered, and why

Stated so a reviewer does not have to discover it:

- **Load and performance.** No benchmarks. The known ceiling - single-writer chain tip - is
  documented ([ARCHITECTURE §7](ARCHITECTURE.md)) but not measured. First thing I would add
  with more time, because §7's claims are currently reasoned rather than evidenced.
- **Multi-process concurrency.** The concurrency tests run in one process. SQLite's
  `BEGIN IMMEDIATE` and `busy_timeout` are designed for the multi-process case, but I have
  not proven it here.
- **Fuzzing** of the canonical serializer. The property tests are hand-rolled shuffles, not a
  generative fuzzer; a fuzzer would be a better use of the same effort at larger scale.
- **Very large chains.** Verification is O(n) and tested at hundreds of records, not millions.
  Checkpointing is designed, not built.
- **The offline verifier's CLI wrapper** is excluded from coverage; its logic (`verifyBundle`)
  is fully tested, its `console.log` presentation is not.
