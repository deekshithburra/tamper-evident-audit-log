# ADR-0006: Credential lifecycle, object-level authorization, and rate limiting

**Status:** Accepted · **Date:** 2026-09-02 · **Supersedes part of** ADR-0002's auth note

## Context

The first cut of this service authenticated with API keys and authorized with roles. A review
identified three gaps, and all three were real:

1. **No credential lifecycle.** A key was a permanent fact - a string in config, valid until
   somebody remembered to delete it. That is the shape of credential handling that produces
   ten-year-old keys nobody can attribute or retire.
2. **No object-level authorization.** Role checks answer "may this principal call this
   endpoint". They do not answer "may this principal see *this record*". A legitimately issued
   `reader` key could walk the entire audit log by iterating event ids without ever failing an
   authorization check. This is Broken Object Level Authorization - OWASP API Security #1, and
   the most exploited API weakness there is.
3. **No rate limiting.** Structural input bounds were in place (body size, payload size, leaf
   count) but nothing stopped a compromised key from looping the most expensive endpoint.

Gap 2 is the serious one. The other two are hygiene; that one is a vulnerability.

## Decision 1 - Credentials have a lifetime and a state

A credential carries `notBefore`, `expiresAt`, `revokedAt` and an optional `scope`, and **every
one is evaluated on each request**, not at boot. A key checked only at startup keeps working
until the next deploy, which can be months after it should have died.

Two configuration forms: `API_KEYS` (simple `secret:role` pairs, for local development) and
`API_CREDENTIALS` (JSON, with the full lifecycle and scope). Both are validated at boot.

**Rotation is why two credentials may share an `id`.** To rotate without a synchronised
cutover you issue a second secret for the same principal, let both work during an overlap
window, move traffic, then let the old one expire. Uniqueness is therefore enforced on the
*secret*, not the id - the id is the principal, the secret is one of possibly two keys that
currently speak for it.

**Expiry is advertised, not just enforced.** Every successful response carries
`X-Credential-Expires-At`, and within the warning window also `X-Credential-Rotation-Due` and a
`Warning` header. A client can automate rotation instead of discovering the lapse as an outage
at 3am. `GET /auth/credentials` gives an operator the same view across every credential -
state, expiry, rotation pressure - without reading deployment config. Secrets never appear.

**Production refuses rather than warns.** A warning in a startup log is a control nobody
enforces, so `loadConfig` refuses to boot in production with development keys, with any
non-expiring credential, or with a credential whose lifetime exceeds
`MAX_CREDENTIAL_LIFETIME_DAYS` (90 by default). A credential nobody has to renew is a
credential nobody will ever retire, and one with a ten-year expiry is the same thing wearing a
hat.

### What this is not
A token service. There is no issuance endpoint, no signing key, no refresh flow. Production
wants short-lived OIDC tokens or mTLS. `CredentialStore` is the seam where that gets replaced:
`authenticate()` returns a `Principal`, and nothing above it cares how the Principal was
established.

## Decision 2 - Object-level scope, enforced in the service layer

A credential may carry an allow-list over the three identity dimensions of a record:
`actorIds`, `resourceTypes`, `resourceIds`. An absent dimension is unrestricted.

**Enforcement lives in `AuditService` / `ComplianceService`, not in middleware.** A middleware
check is bypassed by any future transport that forgets to install it - a queue consumer, a gRPC
surface, a maintenance script. Putting it behind the service method means the scope travels
with the operation.

Three enforcement shapes, and the difference between them is the interesting part:

| Situation | Response | Why |
|---|---|---|
| Collection query, no filter given | Scope injected as an `IN` filter | An unfiltered query returns what the credential may see, not everything |
| Collection query naming an out-of-scope value | **403** | The caller supplied the value themselves; refusing it reveals nothing new |
| Single record outside scope | **404** | See below |
| Export naming an out-of-scope subject | **403** | An empty bundle would read as "this client has no history" - a different and misleading claim |

**The 404 is the load-bearing decision.** Returning 403 for an out-of-scope record confirms
that the event id exists, which turns the endpoint into an existence oracle: an attacker
enumerates ids, and "403" versus "404" tells them exactly which records are real. "Not found"
and "not yours" must be indistinguishable from outside. There is a test that asserts the two
responses are byte-identical apart from the id the caller supplied.

An empty scope allow-list (`[]`) matches **nothing**, not everything. The SQL builder emits
`1 = 0` rather than dropping the clause, because the natural bug here - drop an empty `IN ()`
to avoid a syntax error - silently widens the scope from "nothing" to "everything".

## Decision 3 - Rate limiting keyed by credential, in three cost classes

**By credential, not by IP.** Every caller is a server, usually behind shared egress, so an IP
bucket would either throttle every application together or be trivially evaded. The credential
is what we want to hold accountable and what appears in the audit trail.

**Three budgets, because the costs differ by orders of magnitude.** A write is bounded work. A
chain verification, export or compliance report is O(n) over the entire log - one caller
looping `/audit/verify` degrades the service for everyone, and no sensible write budget would
stop them. Defaults per minute: 1200 writes, 600 reads, **30 expensive**.

**Fixed window, in memory.** Exact, allocation-free and explainable; the cost is a burst of up
to 2x across a window boundary. Its real limitation is that it is per-instance - behind two
replicas the effective limit doubles. Production wants a shared counter (Redis `INCR` with TTL)
or an API gateway. That is a deployment change, not a code change: `RateLimiter` is an
interface with one method, and the in-memory implementation is one of two already in the tree.

The clock is injected so tests step across window boundaries deterministically instead of
sleeping. The window map is evicted on rollover, because a rate limiter that can be turned into
a memory-exhaustion vector is worse than none.

## Consequences

- Responses carry `X-RateLimit-Limit`, `-Remaining`, `-Reset`, and `Retry-After` on a 429, so
  clients can pace themselves rather than retrying blindly.
- Two new error codes (`CREDENTIAL_EXPIRED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_NOT_YET_VALID`,
  `RATE_LIMITED`) let a client distinguish "rotate your key" from "you were never allowed" from
  "slow down" - three different problems with three different fixes.
- Rate limiting is disabled in the test environment by default; it is exercised deliberately in
  its own suite. Leaving it on globally would make unrelated suites fail intermittently as they
  grew, which is how a useful control gets switched off permanently.
- 40 tests cover these three areas (`credentials`, `credential-lifecycle`,
  `object-authorization`, `rate-limit`).

## What is still missing, stated plainly

- **Per-credential quotas beyond rate** (daily caps, burst credit) are not implemented.
- **Anomaly detection** - "this credential just read 400 clients in a minute" - is a
  surveillance concern the compliance read model would feed, not something this service does.
- **Scope is static configuration.** A real deployment binds it to an identity provider's
  claims rather than a JSON blob in the environment.
