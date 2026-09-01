# The Three Scenarios: Decomposition, Execution, Validation

One page per scenario: how it was broken down, how it was built, and how I know it works.
Scenario C's reasoning is long enough to warrant its own document
([SCENARIO_C.md](SCENARIO_C.md)); this file covers its execution and validation.

---

## Scenario A - Greenfield: Core Audit Log Service

### Decomposition
`canonical serialization -> hashing primitives -> record hash -> storage -> write API ->
query API -> verification`. The order is forced: nothing can be persisted before the hash
is defined, and nothing can be verified before it is persisted. Verification was treated as
the critical path (T1-T7 in [TASK_PLAN.md](TASK_PLAN.md)) because every other feature is
either an input to it or a consumer of it.

### Execution
| Requirement | Where | Notes |
|---|---|---|
| Write API | `POST /audit/events` | `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, optional `timestamp` |
| Timestamps | `AuditService.resolveOccurredAt` | **Both**: caller-supplied `occurredAt` bounded by clock skew, server-owned `recordedAt`. Documented choice, [REQUIREMENTS §3.1](REQUIREMENTS.md) |
| Append-only | four layers | API surface, repository shape, DB triggers, hash chain ([ADR-0002](adr/0002-append-only-enforcement.md)) |
| Query | `GET /audit/events` | Any combination of `actorId`, `resourceType`, `resourceId`, `eventType`, `from`/`to` |
| Pagination | keyset on `seq` | Not OFFSET: concurrent writes would make pages skip or repeat |
| Hash chain | `domain/record.ts` | SHA-256 over canonical JSON incl. `prevHash` |
| Verification | `GET /audit/verify` | Reports intactness, first violation, violation type, cascade count. 409 when broken |

### Validation
`tests/integration/tamper.test.ts` follows the exact procedure the brief prescribes - write,
verify, **modify a record directly in SQLite**, verify again - for nine distinct attacks,
asserting the violation *type* each time. Two further tests assert what is **not** detectable
(tail truncation) rather than overclaiming. `scripts/demo.sh` steps 1-6 reproduce the whole
procedure over real HTTP with the `sqlite3` CLI doing the tampering.

**Key result:** a payload edit surfaces as `PAYLOAD_ROOT_MISMATCH` naming the exact field; an
identity edit as `CONTENT_HASH_MISMATCH`; a deletion as `SEQUENCE_GAP` plus `LINK_MISMATCH` -
so an investigator learns *what kind of* incident occurred, not merely that one did.

---

## Scenario B - Extension: Retention, Redaction, Export

### Decomposition
All three depend on verification existing and continuing to pass, so the tamper suite was
written first and became the regression gate for everything below.

### Execution

**Retention** (`POST /audit/retention/apply`). The obvious implementation - delete archived
rows, teach the verifier to skip flagged gaps - is a trap: it makes the verifier trust a
mutable flag, so an attacker deletes records 40-60, marks the gap archived, and verification
waves it through. Instead, archival destroys payload plaintext and salts and keeps the entire
hash skeleton, so `recordHash` stays recomputable and **the verifier needs no exception at
all**. Requirement B2 ("no false positive break") is met structurally rather than by a
carve-out. [ADR-0004](adr/0004-retention-archival.md).

**Redaction** (`POST /audit/events/:eventId/redactions`). The real problem the brief points
at: the hash covers the payload, so deleting a value should break the chain. Solved by never
hashing plaintext directly - each field is committed under its own random salt, the leaves
form a Merkle root, and the root is what the record hash covers. Redaction deletes the value
**and the salt** and keeps the leaf digest; the root, the record hash and the chain are
byte-identical afterwards. Deleting the salt is the detail that matters: an unsalted
commitment to a 9-digit account number is seconds of brute force from being recovered, so
without it the "redacted" record would still contain the sensitive data.
[ADR-0003](adr/0003-redaction-scheme.md) records the three alternatives I rejected.

**Export** (`GET /audit/export?resourceId=|actorId=`). A self-contained bundle with records,
leaf digests, surviving salts, chain context and a bundle hash, verifiable by
`npm run verify:bundle` - which imports only the pure hashing primitives, no database and no
service code. The bundle is explicit that a *filtered slice is not a contiguous chain*: it
carries the global chain head so a recipient can demand a completeness proof the slice itself
cannot give.

### Validation
- `retention.test.ts` - archive 20 records, verify: intact, no violation, no special flags.
  Also asserts the hash skeleton is byte-identical before and after, that archived records
  are excluded from queries by default, and that tampering with an *archived* record is still
  caught (archival must not become a laundering route).
- `redaction.test.ts` - the central assertion is `recordHash` identical before and after.
  Plus: salt destroyed, only named fields removed, array elements nulled rather than spliced
  (splicing would renumber siblings and read as tampering), redactions recorded in the chain,
  admin-only, and a payload edit disguised as a redaction still detected.
- `export.test.ts` - every check runs through the offline verifier; four separate bundle
  tampering attempts each fail as expected, including one that rewrites the manifest to match
  a doctored record.

---

## Scenario C - Ambiguous: Compliance Reporting

Full reasoning in **[SCENARIO_C.md](SCENARIO_C.md)**: five ambiguities, six questions I would
ask, five assumptions with reversal costs, and an explicit list of what I scoped out.

### Execution
`GET /audit/reports/client-data-access`. The design follows from one observation that sits
upstream of any code: **a log that records only writes cannot answer a question about reads**,
so the primary deliverable is a contract with producing applications about what they emit.
The report then adds three things a plain query cannot: it publishes the scope it applied
(so its assumptions can be challenged), it carries chain-integrity evidence (so it is
evidence rather than a spreadsheet), and it appends its own audit event (so the auditors are
audited).

### Validation
`compliance-report.test.ts` - filters correctly, excludes writes and non-client resources,
surfaces accesses lacking a stated purpose as a finding, carries integrity evidence, reports
a tampered chain while still returning data, includes archived accesses, and appends
`COMPLIANCE_REPORT_GENERATED` to the same chain. Demo steps 9 and 11 show the same report
before and after archival, making the cost of retention visible rather than hiding it.
