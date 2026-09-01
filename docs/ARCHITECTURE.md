# Architecture

## 1. Components

```
                    HTTP (JSON)
                         |
              +----------v-----------+
              |  api/                |   auth (API key -> role -> capability)
              |  routes, schemas,    |   validation (zod, strict, bounded)
              |  auth, error-handler |   one error->HTTP translation point
              +----------+-----------+
                         |
              +----------v-----------+
              |  services/           |   AuditService     append / query / retention
              |  audit, compliance,  |   ComplianceService Scenario C read model
              |  verification        |   verifyChain      pure, iterable-driven
              +----------+-----------+
                         |
              +----------v-----------+
              |  storage/            |   AuditRepository  append-only, no update path
              |  repository, schema  |   SQLite + triggers + UNIQUE constraints
              +----------+-----------+
                         |
              +----------v-----------+
              |  domain/             |   canonical  deterministic serialization
              |  canonical, hash,    |   hash       SHA-256, domain separation
              |  commitments, record |   commitments salted leaves -> Merkle root
              +----------------------+   record     the hashed core + HASHED_FIELDS
                         ^
                         |
              +----------+-----------+
              |  cli/verify-bundle   |   imports domain/ ONLY - no service, no db
              +----------------------+
```

The dependency arrows point one way. `domain/` imports nothing from the layers above it,
which is what lets the offline verifier reuse the exact hashing code the server runs while
sharing none of its infrastructure.

## 2. Data model

`audit_events`, one row per record. The columns split into two groups, and the split *is*
the security model:

**Hashed (immutable, covered by `recordHash`)**
`seq`, `event_id`, `event_type`, `actor_id`, `resource_type`, `resource_id`, `occurred_at`,
`recorded_at`, `payload_root`, `prev_hash`, `alg`. Plus `leaves_json`, which is not hashed
directly but is covered transitively through `payload_root`.

**Mutable by policy only (never hash inputs)**
`payload_json`, `field_salts_json`, `redactions_json`, `lifecycle_state`, `archived_at`.

Retention and redaction touch only the second group. That is the entire reason they cannot
break the chain, and it is enforced by `BEFORE UPDATE` triggers rather than by convention.

Constraints doing real work: `UNIQUE(prev_hash)` makes a forked chain impossible;
`UNIQUE(record_hash)` and `UNIQUE(event_id)` prevent duplication; a `CHECK` bounds
`lifecycle_state`; a `BEFORE DELETE` trigger refuses every delete.

## 3. The hash chain

```
recordHash(n) = SHA256( "audit-record-v1" || canonicalJSON({
      seq, eventId, eventType, actorId, resourceType, resourceId,
      occurredAt, recordedAt, payloadRoot, prevHash, alg }) )

prevHash(n)   = recordHash(n-1),      prevHash(1) = 0x00 * 32
```

`prevHash` is *inside* the hash, not stored beside it. That single detail is what makes
this a chain rather than a list of independent digests: recomputing record *n* requires
record *n-1*'s digest, so altering any record invalidates every record after it.

Canonical serialization (`domain/canonical.ts`) makes the digest reproducible on any
runtime: sorted keys, no insignificant whitespace, `-0` normalized, and loud rejection of
`NaN`/`Infinity`/`undefined` instead of lossy coercion. Domain-separation tags and
length-prefixed parts (`domain/hash.ts`) prevent one context's bytes being reinterpreted as
another's.

## 4. Payload commitments

The record hash covers a Merkle root, never plaintext:

```
leaf_i       = SHA256("audit-field-v1" || path_i || salt_i || canonicalJSON(value_i))
payloadRoot  = SHA256("audit-payload-v1" || leafCount || merkleFold(sorted leaves))
```

One random 128-bit salt per leaf. Redaction deletes `value_i` **and** `salt_i` and retains
`leaf_i`, so the root - and therefore the chain - is unchanged. Full rationale, options
considered, and limitations in [ADR-0003](adr/0003-redaction-scheme.md).

## 5. Threat model - what is and is not guaranteed

Stated plainly, because a security claim without its boundary is a marketing claim.

| Attack | Detected? | How |
|---|---|---|
| Edit a payload value in the store | Yes | Leaf re-derives differently, root mismatch |
| Edit an identity field | Yes | `recordHash` recomputation mismatch |
| Delete a record from the middle | Yes | Sequence gap **and** link mismatch |
| Reorder or splice records | Yes | Link mismatch (and `UNIQUE(prev_hash)` usually blocks it first) |
| Delete the first record | Yes | Genesis mismatch |
| Re-sign one record after editing it | Yes | The next record's `prevHash` still names the old digest |
| Downgrade the hash algorithm | Yes | `alg` is a hash input; unsupported values are reported |
| Insert a field into a payload | Yes | Injected leaf changes the root |
| Mutate a record through the app | Yes - prevented | No API path, no repository method, triggers abort |
| **Delete the newest N records (tail truncation)** | **No** | The remainder is internally consistent |
| **Rewrite the whole chain from record k forward** | **No** | An attacker who recomputes every subsequent hash produces a valid chain |

The last two share one root cause and one fix: nothing inside the data can attest to what
the head *should* be. The mitigation is an anchor the attacker does not control - publish
the chain head periodically to an external witness (a counterparty log, a timestamping
authority, object storage under an object-lock retention policy). Then rewriting history
requires forging anchors held elsewhere. Designed for in
[ADR-0002](adr/0002-append-only-enforcement.md); deliberately not implemented in a 2-3 day
prototype, because it is a deployment concern more than a code one - but it is the honest
boundary of what this implementation guarantees, and the tamper suite asserts both limits
rather than papering over them.

## 6. Security posture

- **AuthN**: API keys, compared in constant time, presented via `X-API-Key` or a bearer
  token. Prototype-grade and labelled as such: bearer secrets with no expiry or rotation.
  Production wants mTLS or short-lived OIDC tokens; the middleware boundary does not change.
- **AuthZ**: four roles mapped to capabilities. `writer` cannot read - a compromised event
  producer is the most exposed component, since it lives inside every application, and must
  not be able to read the history it contributes to. Only `admin` can redact or run retention.
- **Input**: strict schemas, no unknown keys (a silently ignored `actorID` typo would return
  the whole log while the caller believed they had filtered), bounded string lengths, a
  256 KB body cap, 64 KB payload cap, 512-leaf and depth-12 structural caps.
- **Output**: field salts are never exposed on read paths; they travel only in exports,
  where the recipient already holds the plaintext.
- **Logging**: authorization headers and payload bodies are redacted at the logger. The log
  is not the audit trail and must not become a second, unprotected copy of it.
- **Errors**: stable machine-readable codes; unexpected errors never leak a message or stack.

## 7. Scaling beyond this prototype

The one global chain serializes writes on a single tip - roughly single-node SQLite write
throughput. Accepted for a prototype and quantified rather than hidden. The path beyond it:

1. **Postgres** behind the same `AuditRepository` interface: concurrent readers, real roles,
   column-level `REVOKE UPDATE` in place of triggers.
2. **Checkpoints**: sign the chain head every N records so verification can start from the
   last trusted checkpoint instead of walking O(n) from genesis.
3. **Sharded chains** keyed by tenant, each anchored into a periodic global Merkle root.
   Restores write parallelism while keeping one head to publish - but it weakens the
   cross-shard deletion guarantee, which is exactly why it is not the starting design.
4. **External anchoring** (§5), which is worth more than all of the above.

## 8. API summary

| Method | Path | Capability | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness, record count, chain head |
| POST | `/audit/events` | `events:write` | Append an event |
| GET | `/audit/events` | `events:read` | Filter + paginate |
| GET | `/audit/events/:eventId` | `events:read` | Fetch one record |
| PUT/PATCH/DELETE | `/audit/events*` | - | **405**, with the reason |
| GET | `/audit/verify` | `chain:verify` | Verify chain; **409** if broken |
| POST | `/audit/retention/apply` | `retention:apply` | Archive past the window |
| POST | `/audit/events/:eventId/redactions` | `records:redact` | Erase payload fields |
| GET | `/audit/export` | `records:export` | Verifiable bundle |
| GET | `/audit/reports/client-data-access` | `reports:read` | Scenario C report |
