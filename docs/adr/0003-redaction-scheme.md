# ADR-0003: Chain-preserving structured redaction

**Status:** Accepted · **Date:** 2026-08-31

## Context
The genuine tension the brief points at: the record hash covers the payload, so deleting a
sensitive value changes the hash and breaks the chain. Privacy law says the value must be
destroyable. Both requirements are real.

## Options considered

| # | Option | Why rejected / chosen |
|---|---|---|
| 1 | Delete the value, accept the break | Destroys the guarantee. Rejected. |
| 2 | Delete the value, recompute all downstream hashes | Rewriting history is exactly the capability the system exists to prevent. Rejected outright. |
| 3 | Encrypt payload, delete the key ("crypto-shredding") | Ciphertext stays put so the hash holds. But key management is per-field or you shred whole records, and "deleted" ciphertext is still retained personal data under some regulators' reading. Rejected as heavier and legally murkier. |
| 4 | **Hash the payload field-by-field into a Merkle root; keep the leaf digest, destroy the value** | **Chosen.** |

## Decision — salted per-field commitments under a Merkle root

At write time the payload is flattened to leaf paths (`account.number`, `items.0.id`).
For each leaf:

```
salt_i = 128 random bits                        (stored beside the value)
leaf_i = SHA256("audit-field-v1" || path_i || salt_i || canonicalJSON(value_i))
```

The leaves are sorted by path and folded into a Merkle root, `payloadRoot`, which is what
the record hash actually covers — **the record hash never covers the plaintext directly.**

Redacting field *p* deletes `value_p` **and `salt_p`**, retaining `leaf_p`. `payloadRoot` is
unchanged, `recordHash` is unchanged, the chain is untouched. Verification passes.

### Why the salt, and why destroying it matters
Without a salt, `leaf = H(path || value)` is trivially brute-forceable for exactly the
fields worth redacting — a 9-digit account number is 10⁹ guesses, seconds of work. The
retained leaf would *be* the sensitive data. The salt makes the commitment hiding; deleting
the salt at redaction time makes the erasure irreversible even for the operator. This is
the detail that turns a superficially plausible scheme into a defensible one.

### Redaction is itself audited
Every redaction appends a `PAYLOAD_REDACTED` meta-event *to the same chain*, capturing who
redacted, which record, which field paths, and the stated reason. Redaction is a privileged
operation, so the log records its own erasures — the trail of what was removed survives even
though the values do not.

## Consequences / limitations (stated, not hidden)
- A third party can verify **integrity** of a redacted record but cannot re-derive the
  redacted leaf from data they hold — they verify `leaf_p` as an opaque committed value
  covered by the root. Integrity survives; independent *content* attestation for that one
  field does not. This is inherent to erasure, not an artefact of this design.
- Leaves are keyed by path, so the *shape* of the payload (which field names existed) is
  still visible after redaction. Usually desirable for audit. If a field *name* is itself
  sensitive, redact the whole payload object at its parent path.
- Merkle proofs are computed over the full leaf set (O(n) per record, n = leaf count). Fine
  for audit payloads; a payload with 10⁵ leaves is rejected by the size limit (X2) instead.
