# ADR-0001: Hash chain construction and algorithm choice

**Status:** Accepted · **Date:** 2026-08-30

## Context
Every record must carry a hash of its own content and of its predecessor, such that any
modification to past history is detectable.

## Decision

**Algorithm: SHA-256.** Collision-resistant, ubiquitous, hardware-accelerated, FIPS 140
approved, and available in Node's `crypto` with no dependency. SHA-3/BLAKE3 are fine
alternatives but buy nothing here; MD5/SHA-1 are excluded (practical collisions — an
attacker who can craft two payloads with the same digest can swap history undetected).

The algorithm is stored per record in an `alg` column and is a hash input, so a future
migration to SHA-384 can coexist with historical records rather than forcing a rewrite.

**Record hash:**

```
recordHash = SHA256( "audit-record-v1" || canonicalJSON({
    seq, eventId, eventType, actorId, resourceType, resourceId,
    occurredAt, recordedAt, payloadRoot, prevHash, alg
}) )
```

**Chain link:** `prevHash` of record *n* is the `recordHash` of record *n-1*.
For `seq = 1`, `prevHash` is the genesis constant (64 zero characters).

**`prevHash` is inside the hash, not beside it.** This is the property that makes the
structure a chain rather than a list of independent hashes: recomputing record *n*
requires record *n-1*'s digest, so altering any record invalidates every record after it.

## Canonical serialization
Hashing raw `JSON.stringify` output is a correctness bug waiting to happen: key order,
unicode escaping and number formatting are not guaranteed stable across runtimes, so a
verifier on a different platform could report a false tamper. `src/domain/canonical.ts`
defines an explicit canonical form (RFC 8785-style): recursively sorted object keys, no
insignificant whitespace, rejection of values with no stable representation
(`NaN`, `Infinity`, `undefined`, functions, `-0` normalized to `0`). A domain-separation
prefix (`"audit-record-v1"`, `"audit-field-v1"`) prevents a payload from being crafted to
collide with a record digest.

## Consequences
- Verification is O(n) — the whole chain must be walked. Acceptable at prototype scale;
  ADR-0002 covers checkpointing for large chains.
- Writes must serialize to read the current tip. Enforced by an `IMMEDIATE` SQLite
  transaction, not by application-level locking.
