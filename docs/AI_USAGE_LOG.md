# AI Usage Log and Traceability Notes

AI assistant: **Claude (Claude Code)**, used throughout as an accelerator inside tasks I
defined, reviewed and owned. This log records what I asked for, what I accepted, what I
changed, and what I rejected outright - with the reasoning, because the reasoning is the
part that shows whether the engineering judgement was mine.

The pattern I settled into: **I decide the design, AI writes the first draft, I review it
as I would a colleague's pull request, and the tests arbitrate.** Where those three
disagreed, the tests won and the code changed.

## How tasks were framed

Every non-trivial prompt carried four things: intent, constraints, acceptance criteria, and
the technical context the assistant could not infer. A representative example, for the
redaction work:

> Implement chain-preserving redaction. Constraint: `recordHash` must be byte-identical
> before and after redacting a payload field - this is non-negotiable, the chain cannot
> move. The payload is committed as salted per-field leaves under a Merkle root (see
> `src/domain/commitments.ts`); the record hash covers only the root. Acceptance: redact a
> field, assert the record hash is unchanged, assert the chain still verifies, assert the
> salt is destroyed along with the value. Do not recompute any downstream hashes under any
> circumstances.

Vague prompts produced plausible code that failed review. Prompts that stated the invariant
up front produced code I could actually assess against something.

## Session log

### Session 1 - Requirement analysis and design (no production code written)

Deliberately spent the first block of work on analysis, because the redaction requirement
in Scenario B constrains the storage format in Scenario A. Getting that order wrong means a
data migration halfway through a 2-3 day exercise.

| Prompt intent | Outcome | Decision |
|---|---|---|
| Enumerate ambiguities in the brief, with options for each | 9 candidate ambiguities | **Modified.** Kept 6 as genuine, merged 2, dropped 1 as invented. Recorded in REQUIREMENTS §3. |
| Argue both sides of caller- vs server-supplied timestamps | Balanced analysis | **Accepted the analysis, made my own call:** store both, bound the caller's claim by clock skew. The framing that decided it - a client owning the only timestamp can backdate into settled history - came from the AI's argument; the resulting policy is mine. |
| Options for chain granularity (global vs per-resource) | Four options with trade-offs | **Accepted** global single chain; the observation that per-resource chains let an attacker drop a whole resource undetected is the one that settled it. |

**Rejected in this session:** a proposal to store the payload as a single hashed blob. It is
simpler and passes every Scenario A test, but makes Scenario B redaction impossible without
a storage migration. Pulling field-level commitments forward cost ~2 hours and saved a
format change later. This is recorded in [TASK_PLAN.md](TASK_PLAN.md) as a plan change,
because it was one.

### Session 2 - Cryptographic core

| Prompt intent | Outcome | Decision |
|---|---|---|
| Canonical JSON serializer, deterministic across runtimes | Sorted-key serializer | **Accepted with additions.** The draft coerced `NaN` to `null`. Silently coercing a value that cannot be hashed reproducibly is exactly how a false tamper report gets born, so I made all non-representable values a hard rejection with the offending path named. |
| Merkle root over payload leaves | Standard binary fold | **Modified.** The draft duplicated the last node on an odd level - the well-known second-preimage ambiguity. I bound the leaf count into the root instead. |
| Hash helper concatenating parts | Simple concatenation | **Rejected and rewritten.** `("ab","c")` and `("a","bc")` hashed identically. Added length prefixes; that is a real substitution attack when one part is attacker-controlled. |
| Domain separation tags | Suggested by the assistant, unprompted | **Accepted.** A good catch I would have reached later and more painfully. |

**Defect found by the tests, fixed in the code:** `recomputeRoot` reported an injected
payload field in `mismatchedPaths` but left the Merkle root unchanged - so the chain
verifier, which compares roots, would have passed a payload with an added field. The AI's
first instinct was to have callers check `mismatchedPaths`. I rejected that: detection has
to live in the value the chain covers, not in a side channel a caller might not read. See
commit `9e23e2f`.

### Session 3 - Storage and append-only enforcement

| Prompt intent | Outcome | Decision |
|---|---|---|
| Append-only SQLite schema with triggers | Triggers on all columns | **Modified.** Blocking updates to *every* column makes redaction and archival impossible. Narrowed to the hashed columns, which forced me to write down exactly which columns are hash inputs - that list became `HASHED_FIELDS` and is now the stated security boundary of the system. |
| Concurrent append safety | `db.transaction(...)` | **Modified to `.immediate()`.** A deferred transaction reads the chain tip *before* taking the write lock, which is precisely the race that forks a chain. This is the kind of bug that passes every test until production load finds it. |
| Pagination | OFFSET-based | **Rejected.** Concurrent writes make offset pages skip or repeat records - unacceptable when the reader is reconciling a complete history. Rewritten as keyset pagination on `seq`. |

### Session 4 - Retention, redaction, export

| Prompt intent | Outcome | Decision |
|---|---|---|
| Retention/archival | Delete archived rows; verifier skips flagged gaps | **Rejected outright.** This makes the verifier trust a mutable flag: delete records 40-60, mark the gap archived, verification passes. The soft-delete flag becomes the tamper vector. Redesigned as content-only archival, which *removed* a verifier special case rather than adding one - a good sign the second design was right. [ADR-0004](adr/0004-retention-archival.md). |
| Redaction scheme | Four options offered | **Accepted the option, added the critical detail.** The draft retained the salt after redaction. An unsalted-in-practice commitment to a 9-digit account number is seconds of brute force from recovery, so the "redacted" record would still contain the sensitive data. Destroying the salt with the value is what makes the erasure irreversible. |
| Export bundle | Bundle described as "independently verifiable" | **Modified the claim, not just the code.** A filtered slice is not a contiguous chain and cannot prove completeness. I made the verifier say so in its own output and included the global chain head so a recipient can demand that proof separately. Overclaiming here would have been the worst kind of error in a system whose entire value is trustworthiness. |

### Session 5 - Scenario C

Used AI mainly as a sounding board rather than a code generator. The decisive insight -
that a log recording only writes cannot answer a question about reads, so the real
deliverable is a contract with producing applications - came out of arguing the requirement
back and forth rather than from any generated code.

**Rejected:** a first draft that returned rows and nothing else. It satisfies the sentence
and fails the purpose. Added the published scope, the integrity evidence, and the
self-auditing behaviour, each for a reason recorded in [SCENARIO_C.md](SCENARIO_C.md).

**Accepted:** surfacing accesses with no stated purpose as a counted finding rather than
either dropping them or hard-failing writes that lack one.

### Session 6 - Tests, and the debugging that mattered

Tests were specified by me (what to assert, and which attack shapes) and drafted by AI. Two
things I insisted on that a generated suite would not have produced on its own:

1. **Tamper tests must edit SQLite directly**, dropping the triggers first. Testing our own
   endpoints only proves we didn't write an update method.
2. **Tests that assert limits**, not just capabilities - tail truncation is undetectable,
   and a filtered export cannot prove completeness. Both are now executable documentation.

The suite then flushed out two real code defects (emptied containers reading as tampering;
the retention cutoff off-by-one) and one environment defect that cost the most time: test
servers binding dual-stack, so requests to `127.0.0.1:<port>` sometimes reached an unrelated
local process. The AI's early suggestions were to retry, to serialize the suite, and to
raise timeouts - all of which would have masked it. The giveaway was a 401 whose response
body was another service's error envelope; that is not a flake, that is a misdirected
request. I asked for the actual response text instead of the status code, and the cause was
obvious within one run. Recorded in [TESTING.md](TESTING.md).

### Session 7 - Review response: API security controls and crash testing

A review of the first submission identified three gaps - no credential lifecycle, no
object-level authorization, no rate limiting - plus a request for a crash simulation and better
test reporting. All three security gaps were fair; the second was a genuine vulnerability
rather than missing polish.

| Prompt intent | Outcome | Decision |
|---|---|---|
| Add credential expiry and revocation | Lifecycle fields checked at boot | **Modified.** Checking at boot means a key keeps working until the next deploy, which can be months. Moved every check to request time. |
| Add object-level authorization | Middleware that filtered results | **Modified, and moved.** A middleware check is bypassed by any future transport that forgets to install it, so enforcement went into the service layer where the scope travels with the operation. |
| Out-of-scope record response | 403 Forbidden | **Rejected.** A 403 confirms the id exists, which is all an attacker needs to enumerate a log they cannot read. Changed to 404, with a test asserting the two responses are indistinguishable apart from the caller's own echoed id. |
| Empty scope allow-list handling | Dropped the `IN ()` clause to avoid a SQL syntax error | **Rejected - this one was dangerous.** Dropping the clause silently widens the scope from "nothing permitted" to "everything permitted". Emits `1 = 0` instead. |
| Rate limiter | One global bucket keyed by IP | **Rejected.** Every caller here is a server behind shared egress, so an IP bucket throttles everyone together or is trivially evaded. Rekeyed by credential and split into three cost classes, because O(n) verification and a single write do not belong in one budget. |
| Rate limit tests | `setTimeout` waits to cross the window | **Modified.** Injected the clock instead: a limiter tested with sleeps is slow *and* flaky under load. |
| Crash simulation | Closed and reopened the database in-process | **Rejected.** That tests nothing a normal test does not. Replaced with a spawned child process killed by an uncatchable SIGKILL mid-write. |

**A bug I found by reading the output rather than the assertion.** The crash *demo* script
initially launched the writer via `npx`, so the PID being killed was npx's - the real writer
survived and kept committing. The tests were correct (they spawn `process.execPath` directly),
but the demo was quietly proving nothing. The tell was the record count drifting between two
reads in the same script. Fixed by launching node directly.

## Where AI helped most, and least

**Most:** breadth of options at design time (the four redaction schemes, weighed honestly);
first drafts of mechanical code; test scaffolding once I had specified the assertions;
catching things I would have reached late (domain separation); and drafting documentation
prose from decisions I had already made.

**Least:** anything requiring a judgement about *trust*. The session-7 additions extended the
pattern exactly: a 403 that leaks existence, and an empty allow-list that fails open. Both were
working code. Every significant correction in
this log is the same shape - the generated code was functionally correct and quietly weakened
a security property. Retained salts, mutable flags the verifier trusts, side-channel
detection, overclaimed guarantees. None would fail a test that wasn't written specifically to
catch it, and none would be caught by a reviewer skimming for correctness. That is the part
that had to be human, and it is the part I would expect to be asked about.

## Secure and controlled use

- No client data, credentials, or proprietary material was pasted into any prompt. Test
  fixtures use obviously synthetic values (`555-01-0001`, `198.51.100.4` from the
  documentation-reserved range).
- No generated code was committed without being read line by line. Where I did not
  understand why a line was there, it came out.
- The cryptographic core was the most heavily reviewed area and carries the highest test
  density, because it is where a subtle generated mistake would be least visible and most
  damaging.
- Every commit message records what changed and why, so the reasoning is in the repository
  rather than only in this file.
