# Tamper-Evident Audit Log Service

An append-only audit log that records an immutable history of events and makes any later
modification, deletion or reordering **detectable** through a SHA-256 hash chain - while
still supporting the two things a real compliance system needs and a naive hash chain
forbids: **retention** and **redaction of sensitive fields**.

169 tests · 95.8% statement coverage · runs in ~2 seconds.

---

## Quick start

```bash
node --version          # 20.10+ required (developed on 22)
npm install
cp .env.example .env     # development API keys are in here
npm test                 # 169 tests
npm run dev              # http://localhost:3000
```

Then, in another terminal:

```bash
curl -s localhost:3000/health | jq

# write an event
curl -s -X POST localhost:3000/audit/events \
  -H 'X-API-Key: dev-writer-key' -H 'Content-Type: application/json' \
  -d '{"eventType":"USER_LOGIN","actorId":"user-1","resourceType":"session",
       "resourceId":"s-1","payload":{"ip":"198.51.100.4","mfa":true}}' | jq

# query
curl -s 'localhost:3000/audit/events?actorId=user-1' -H 'X-API-Key: dev-reader-key' | jq

# verify the chain
curl -s localhost:3000/audit/verify -H 'X-API-Key: dev-auditor-key' | jq
```

### See the whole thing work, including tamper detection

```bash
npm run demo        # needs jq and the sqlite3 CLI
```

`scripts/demo.sh` follows the validation procedure from the brief end to end: write events,
query them, verify, **modify a record directly in SQLite with the `sqlite3` CLI**, verify
again and watch the break get caught at the exact record - then demonstrates redaction with
an unchanged record hash, retention with no false break, a verifiable export checked
offline, and the Scenario C compliance report.

---

## Start here (reviewer's path)

| Read this | For |
|---|---|
| [docs/ENGINEERING_SUMMARY.md](docs/ENGINEERING_SUMMARY.md) | Plan, decisions, risks, limitations - the 5-minute version |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | How the brief was normalized; every ambiguity and how it was resolved |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data model, hash design, **threat model incl. what is not caught** |
| [docs/SCENARIOS.md](docs/SCENARIOS.md) | Scenarios A, B, C: decomposition, execution, validation |
| [docs/SCENARIO_C.md](docs/SCENARIO_C.md) | The ambiguous requirement worked in full |
| [docs/adr/](docs/adr/) | Five decision records, each with the options rejected |
| [docs/TESTING.md](docs/TESTING.md) | Approach, the defects tests found, and what is **not** covered |
| [docs/AI_USAGE_LOG.md](docs/AI_USAGE_LOG.md) | What was prompted, accepted, modified, rejected - and why |
| [docs/TASK_PLAN.md](docs/TASK_PLAN.md) | Task decomposition, dependencies, and where the plan changed |

If you read one file of code, read
[`src/domain/commitments.ts`](src/domain/commitments.ts) - the salted per-field Merkle
commitments are what make redaction possible without touching the chain.

---

## How it works

Each record stores a hash of its own content **and** of the record before it:

```
recordHash(n) = SHA256("audit-record-v1" || canonicalJSON({
    seq, eventId, eventType, actorId, resourceType, resourceId,
    occurredAt, recordedAt, payloadRoot, prevHash, alg }))

prevHash(n)   = recordHash(n-1)          prevHash(1) = 0x00 * 32   (genesis)
```

Because `prevHash` is *inside* the hash, modifying any record invalidates its own digest and
every digest after it. `GET /audit/verify` walks the chain and reports the first
inconsistency and its type.

**The payload is never hashed directly.** Each field is committed under its own random salt;
the leaves form a Merkle root; the root is what the record hash covers:

```
leaf_i      = SHA256("audit-field-v1" || path || salt_i || canonicalJSON(value))
payloadRoot = SHA256("audit-payload-v1" || leafCount || merkleFold(sorted leaves))
```

Redaction deletes the value **and its salt** and keeps the leaf digest - so the root, the
record hash and the entire chain are unchanged, while the value is unrecoverable even by us.
Archival is the same operation applied to every field, plus a lifecycle marker, which is why
verification needs no special case for archived records.

---

## API

All endpoints except `/health` require an API key (`X-API-Key` or `Authorization: Bearer`).

| Method | Path | Role |
|---|---|---|
| `GET` | `/health` | none |
| `POST` | `/audit/events` | writer, admin |
| `GET` | `/audit/events?actorId=&resourceType=&resourceId=&eventType=&from=&to=&limit=&cursor=&includeArchived=` | reader, auditor, admin |
| `GET` | `/audit/events/:eventId` | reader, auditor, admin |
| `PUT` `PATCH` `DELETE` | `/audit/events*` | **405 - append-only** |
| `GET` | `/audit/verify?fromSeq=` | auditor, admin (409 if broken) |
| `POST` | `/audit/retention/apply` | admin |
| `POST` | `/audit/events/:eventId/redactions` | admin |
| `GET` | `/audit/export?resourceId=\|actorId=` | auditor, admin |
| `GET` | `/audit/reports/client-data-access?from=&to=&clientId=&actorId=` | auditor, admin |

Roles are least-privilege on purpose: a `writer` cannot read the log it writes to, and only
an `admin` can redact. Rationale in [ARCHITECTURE §6](docs/ARCHITECTURE.md).

### Verify an exported bundle offline

```bash
curl -s 'localhost:3000/audit/export?resourceId=acct-1' \
  -H 'X-API-Key: dev-auditor-key' > bundle.json
npm run verify:bundle -- bundle.json
```

The verifier imports only the pure hashing primitives - no database, no service code - which
is what makes "independently verifiable" a real claim rather than a slogan.

---

## Configuration

All via environment variables; see [`.env.example`](.env.example). Invalid configuration
fails at boot, not at the first request.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `DATABASE_PATH` | `./data/audit.db` | SQLite file, or `:memory:` |
| `MAX_CLOCK_SKEW_MS` | `300000` | Bound on caller-supplied `timestamp` |
| `RETENTION_WINDOW_DAYS` | `365` | Default archival window |
| `API_KEYS` | dev keys | `key:role` pairs; `writer`/`reader`/`auditor`/`admin` |
| `MAX_PAGE_SIZE` / `DEFAULT_PAGE_SIZE` | `200` / `50` | Pagination bounds |

The service refuses to start in production with the development keys from `.env.example`.

## Scripts

| Command | Does |
|---|---|
| `npm run dev` | Run with reload |
| `npm test` / `npm run test:coverage` | Tests / with coverage |
| `npm run check` | Typecheck + lint + test |
| `npm run demo` | Full end-to-end demonstration |
| `npm run verify:bundle -- <file>` | Offline bundle verification |
| `npm run build && npm start` | Compile and run |

---

## Honest limitations

This system makes tampering **detectable**, not impossible. An attacker with full write
access to the datastore who rewrites history from record *k* forward, recomputing every
subsequent hash, produces a chain that verifies clean; likewise, deleting the newest records
leaves an internally consistent chain. Both need an anchor held where the attacker cannot
reach it - publishing the chain head periodically to an external witness. That is designed
in [ADR-0002](docs/adr/0002-append-only-enforcement.md), deliberately not implemented here,
and asserted as a known limitation in the tamper test suite rather than left implicit.

The full list is in [ENGINEERING_SUMMARY §4-6](docs/ENGINEERING_SUMMARY.md).
