# Test Report

A committed snapshot of a real run, so a reviewer can see the numbers without running anything.
Regenerate with `npm run test:report`, which writes machine-readable artefacts to `reports/`
(gitignored, because generated output does not belong in version control):

| Artefact | Contents |
|---|---|
| `reports/junit.xml` | Per-test results in JUnit format, for CI test reporting |
| `reports/test-results.json` | Full structured run output including durations |
| `reports/coverage/index.html` | Browsable line-by-line coverage |
| `reports/coverage/lcov.info` | For Codecov / SonarQube / IDE gutters |
| `reports/coverage/coverage-summary.json` | Machine-readable totals |

Run captured: **2026-09-02**, Node 22.22.0, macOS (arm64).

## Run output

```
 ✓ tests/unit/canonical.test.ts                   (7 tests)     52ms
 ✓ tests/unit/commitments.test.ts                 (17 tests)    13ms
 ✓ tests/unit/config.test.ts                      (6 tests)      5ms
 ✓ tests/unit/credentials.test.ts                 (16 tests)    23ms
 ✓ tests/unit/record.test.ts                      (5 tests)      4ms
 ✓ tests/integration/append-only.test.ts          (13 tests)   175ms
 ✓ tests/integration/auth.test.ts                 (32 tests)   312ms
 ✓ tests/integration/compliance-report.test.ts    (12 tests)   312ms
 ✓ tests/integration/concurrency.test.ts          (3 tests)    356ms
 ✓ tests/integration/crash-recovery.test.ts       (4 tests)   2573ms
 ✓ tests/integration/credential-lifecycle.test.ts (10 tests)   103ms
 ✓ tests/integration/export.test.ts               (11 tests)   457ms
 ✓ tests/integration/object-authorization.test.ts (18 tests)   284ms
 ✓ tests/integration/query-api.test.ts            (10 tests)   546ms
 ✓ tests/integration/rate-limit.test.ts           (12 tests)   231ms
 ✓ tests/integration/redaction.test.ts            (12 tests)   238ms
 ✓ tests/integration/retention.test.ts            (11 tests)   791ms
 ✓ tests/integration/tamper.test.ts               (13 tests)   456ms
 ✓ tests/integration/write-api.test.ts            (18 tests)   173ms

 Test Files  19 passed (19)
      Tests  230 passed (230)
   Duration  ~4s
```

## Coverage

```
File               | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s
-------------------|---------|----------|---------|---------|-------------------
All files          |   96.75 |    90.81 |   94.39 |   96.75 |
 src               |     100 |    98.00 |     100 |     100 |
  app.ts           |     100 |      100 |     100 |     100 |
  config.ts        |     100 |    97.72 |     100 |     100 | 190
 src/api           |   96.69 |    91.47 |   92.30 |   96.69 |
  auth.ts          |   96.77 |    96.15 |     100 |   96.77 | 135-137
  credentials.ts   |   96.66 |    97.61 |   83.33 |   96.66 | 145-146
  error-handler.ts |   87.03 |    82.35 |     100 |   87.03 | 32-34,76-79
  rate-limit.ts    |     100 |    90.47 |   85.71 |     100 | 100
  routes.ts        |   99.43 |    88.13 |     100 |   99.43 | 268
  schemas.ts       |   95.19 |    90.90 |     100 |   95.19 | 44-48
 src/domain        |   94.44 |    92.85 |   88.57 |   94.44 |
  access-scope.ts  |   94.11 |    84.44 |     100 |   94.11 | 48-49,82,84
  canonical.ts     |     100 |    96.15 |     100 |     100 | 56
  commitments.ts   |   92.59 |    95.31 |   90.00 |   92.59 | 100-101,120-123
  errors.ts        |   94.44 |      100 |   90.00 |   94.44 | 51-52
  hash.ts          |   88.57 |      100 |   60.00 |   88.57 | 48-49,57-58
  record.ts        |     100 |      100 |     100 |     100 |
 src/services      |   96.22 |    83.80 |     100 |   96.22 |
  audit-service.ts |   95.48 |    83.54 |     100 |   95.48 | 260-261,349-350
  compliance-...ts |   95.48 |    87.17 |     100 |   95.48 | 149-150,217-218
  verification.ts  |   99.03 |    79.16 |     100 |   99.03 | 109
 src/storage       |   98.46 |    94.54 |     100 |   98.46 |
  repository.ts    |   98.39 |    94.54 |     100 |   98.39 | 238-240
  schema.ts        |     100 |      100 |     100 |     100 |
-------------------|---------|----------|---------|---------|-------------------

Statements   : 96.75% ( 1728/1786 )
Branches     : 90.81% (  524/577  )
Functions    : 94.39% (  101/107  )
Lines        : 96.75% ( 1728/1786 )
```

### Thresholds

`vitest.config.ts` enforces **90% statements / 82% branches / 90% functions / 90% lines**. The
run fails if coverage drops below them. They sit a little under the current numbers on purpose:
they are a ratchet against regression, not a target to chase. Chasing 100% would mean writing
tests for `process.exit` paths and log formatting, which adds noise and no confidence.

`src/index.ts` and `src/cli/**` are excluded because they are process bootstrap and console
presentation, exercised by `scripts/demo.sh` rather than by unit tests. The *logic* inside the
CLI (`verifyBundle`) is imported and fully tested by `export.test.ts`; only its `console.log`
wrapper is out of scope. Excluding them keeps the number honest rather than diluting it.

### What the uncovered lines are

Not padding - each is a deliberate gap:

- `error-handler.ts:32-34,76-79` - the `headersSent` re-throw path and the generic 500 handler.
  Reachable only by an error thrown after a response has begun streaming.
- `hash.ts:48-49,57-58` - `sha256Hex` and `isHexDigest`, used by the offline verifier's
  presentation layer.
- `access-scope.ts:48-49` - a scope dimension check unreachable via HTTP, since routes never
  construct a partial scope object directly.
- `commitments.ts:100-101,120-123` - the empty-leaf-set Merkle root and the payload byte-size
  cap, both of which the API's own validation rejects before they are reached.

## Crash simulation

`tests/integration/crash-recovery.test.ts` spawns a real writer process, kills it with an
uncatchable **SIGKILL** mid-write, then reopens the database file. Four scenarios:

| Test | Asserts |
|---|---|
| Durability across SIGKILL | Every acknowledged seq is still present after reopening |
| No torn record | Chain verifies, sequence numbers contiguous from 1 |
| Recovery continues the chain | A new append links to the head that survived the crash |
| Two consecutive crashes | Repeated unclean shutdowns still leave the chain intact |

The property that matters most is the second. A half-written record left behind would be
reported by the verifier as tampering - and a system that cries tamper after every unclean
shutdown is one nobody will believe when it matters.

`npm run demo:crash` runs the same thing visibly. A captured run:

```
2. SIGKILL - no cleanup, no flush, no graceful close
  The writer acknowledged 426 records before it was killed (last seq 426).
  It was midway through a run of 20000: this is a kill during active writing, not after.

3. Reopening the database and checking what survived
{
  "acknowledgedThrough": 426,
  "recordsOnDisk": 426,
  "lastAcknowledgedSurvived": true,
  "chainIntact": true,
  "recordsChecked": 426,
  "firstViolation": null
}
resumed at seq 427, linked to the surviving head: true
  DURABLE and INTACT - no acknowledged write lost, no torn record, chain still verifies.
```

This is the only test that actually checks the `synchronous = FULL` claim rather than restating
it. An audit log that acknowledges a write it can lose on power failure is lying to its caller.

> A note on what this does and does not prove: SIGKILL kills the process, so it proves the
> database survives a process crash with no cleanup. It does not simulate a *host* power loss,
> where the OS page cache is also lost - that needs a VM snapshot or a device-mapper fault
> injector, and is out of scope here. `synchronous = FULL` is what covers that case, and it is
> the setting this test protects from being quietly downgraded.

## Continuous integration

`.github/workflows/ci.yml` runs typecheck, lint and the full suite with coverage on every push
and pull request, publishing the JUnit results and coverage report as build artefacts and
posting a coverage summary to the job summary. The coverage thresholds fail the build, so a
regression is caught at the pull request rather than discovered later.
