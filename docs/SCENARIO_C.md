# Scenario C - Working an Under-Specified Requirement

> Product says: *"Regulators need to be able to audit access to client account data."*

This is the scenario with no right answer, so what follows is the reasoning, not just the
result: the ambiguities I found, the questions I would ask, the assumptions I proceeded
under, what I built, and - explicitly - what I chose not to build.

## 1. Why this cannot be implemented as written

The sentence contains four undefined terms and one unstated actor. Each has multiple
readings that lead to materially different systems:

| Term | Readings I considered |
|---|---|
| "regulators" | An external examiner with a login? An internal compliance officer producing evidence *for* an examiner? An automated feed to a supervisory system? |
| "audit" | Read the raw log? Get a summarised report? Receive continuous surveillance alerts? Attest that the log itself is trustworthy? |
| "access" | Reads only? Reads and writes? Exports and prints? Permission grants that *enable* future access? Failed attempts? |
| "client account data" | Balances? Positions? PII? Statements? Tax documents? Who decides, and is that list stable? |
| (unstated) "be able to" | On demand, self-service? On request with a turnaround? Continuously streamed? |

The trap here is that the sentence is easy to *sound* satisfied: ship a query endpoint,
call it a compliance feature, and it collapses the first time a regulator asks a real
question. The important observation is upstream of the code:

**An audit log that only records writes cannot answer this question at all.** "Who looked
at this client's data" is unanswerable unless reads are themselves recorded as events. So
the primary deliverable of Scenario C is not an endpoint - it is a *contract with the
producing applications* about what they must emit. The endpoint is the easy half.

## 2. Questions I would ask before building

Ordered by how much the answer changes the design:

1. **Do the producing applications emit read events today?** If not, this is a change to
   every consuming application, not a change to the audit service, and the endpoint is
   worthless until they do. *(Highest-impact question by a distance.)*
2. **Is the regulator a direct user of this system, or does compliance produce the report
   for them?** Direct access means external identity federation, per-client scoping, rate
   limits, and a much larger threat surface.
3. **Which resource types are classified as client account data, and who owns that list?**
   If the answer is "the privacy office", this is configuration, not code.
4. **Is a documented purpose-of-access required?** Regulators generally want intent, not
   just occurrence. If it is required, the write API needs a mandatory `purpose` for these
   event types, and that is a schema change with rollout implications.
5. **What retention applies?** Regulatory windows (often 5-7 years) usually exceed privacy
   minimisation pressure. When they conflict, which wins, and who signs off?
6. **Does the report need to be evidentially defensible** - i.e. does the regulator need to
   verify the log wasn't altered before trusting the report?

## 3. Clarified requirement (what I built against)

> An authorised compliance officer can produce, for a stated time window, a complete and
> verifiable record of every read or export of client account data: who accessed what,
> when, and under what stated purpose - together with evidence that the underlying log has
> not been altered.

## 4. Assumptions, and how to reverse each

Each is a decision I would put in front of the product owner. None is hidden in code.

| # | Assumption | If wrong |
|---|---|---|
| C-1 | The consumer is an internal compliance officer (`auditor`/`admin` role), not the regulator directly. | Add external identity federation and per-regulator scoping; the read model is unchanged. |
| C-2 | "Access" means read-shaped events: `RECORD_VIEWED`, `RECORD_EXPORTED`, `RECORD_SEARCHED`, `REPORT_GENERATED`, plus `PERMISSION_GRANTED`/`REVOKED` because granting access is how future access happens. Writes are excluded - a write is a change, and "who changed it" is a different question with a different report. | Extend `ACCESS_EVENT_TYPES`; one constant. |
| C-3 | "Client account data" is a fixed list of resource types (`client_account`, `client_profile`, `client_position`, `client_statement`, `client_tax_document`). | Move to a data-classification registry owned by the privacy office. The code reads a list either way. |
| C-4 | Purpose-of-access is read from a conventional payload field (`purpose`/`reason`/`justification`) and is **optional**, with absences counted and surfaced. | Make it mandatory in `writeEventSchema` for access event types. |
| C-5 | Reporting is on-demand, synchronous, paginated. | Add async generation and delivery for very large windows. |

Assumption C-4 deserves its own note. Making purpose mandatory immediately would break
every existing producer, and a service that rejects audit events is worse than one that
accepts incomplete ones - you lose the record entirely. Instead the report *counts and
lists* accesses with no stated purpose, which turns the gap into a visible compliance
finding and gives the organisation a migration path. Hiding it would have been the real
failure.

## 5. Design decisions that fall out of the clarified requirement

1. **The scope travels with the answer.** The response includes the resource-type and
   event-type lists it applied. A report whose scope is invisible cannot itself be audited,
   and C-2 and C-3 are assumptions the reader should be able to challenge.
2. **Integrity evidence is part of the report, not a separate call.** Every report carries a
   chain verification result and the current chain head. Without it a regulator has a
   spreadsheet; with it they have evidence. If the chain is broken, the report says so
   prominently and *still returns the data* - an investigator chasing a suspected cover-up
   needs both the records and the warning, not an error that tells them nothing.
3. **Generating a report is itself an access to client data, so it appends its own audit
   event.** Otherwise the surveillance surface is the one blind spot in the log. The people
   auditing the log are audited by it.
4. **Archived records are included.** Their payloads are gone, so the purpose reads as
   absent, but the *access itself* is still reported. Omitting them would understate access,
   which is the exact opposite of what a compliance report is for. The demo shows this
   trade-off directly (steps 9 and 11).

## 6. Scope boundary - what I did not build, and why

Deliberate omissions, not oversights:

- **A regulator-facing UI or portal.** Assumption C-1 makes it out of scope, and the brief
  asks for APIs.
- **Mandatory purpose enforcement.** Per C-4, this is a producer-side rollout, not a
  service change I can make unilaterally without breaking every writer.
- **Continuous surveillance alerting** (e.g. "advisor viewed 400 accounts in an hour").
  Genuinely valuable and genuinely a different system: it needs streaming, thresholds,
  case management and an on-call path. The read model here is the input it would consume.
- **Signed/sealed report artefacts** (PDF with a detached signature for submission). The
  bundle export in Scenario B is the mechanism; wiring it to a report format is packaging
  work that would add pages and no new engineering insight.
- **Cross-system correlation.** This service can only report what it was told. If an
  application reads client data without emitting an event, no report can reveal it. That is
  a limitation of the whole approach and it belongs in the conversation with the regulator,
  not buried in a footnote here.

## 7. What was implemented

`GET /audit/reports/client-data-access?from=&to=[&clientId=][&actorId=][&limit=][&cursor=]`
requiring the `reports:read` capability. Implementation in
[`src/services/compliance-service.ts`](../src/services/compliance-service.ts), tests in
[`tests/integration/compliance-report.test.ts`](../tests/integration/compliance-report.test.ts).

Returns: the criteria and the scope applied; a summary (total, distinct actors, distinct
clients, breakdown by event type, count of accesses with no stated purpose); paginated
entries; and an integrity block carrying the verification result and chain head.
