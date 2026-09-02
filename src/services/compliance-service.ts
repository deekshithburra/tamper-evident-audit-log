/**
 * Scenario C: "Regulators need to be able to audit access to client account data."
 *
 * The requirement as given is not implementable - see `docs/SCENARIO_C.md` for the five
 * ambiguities, the questions I would ask, and the assumptions I proceeded under. This module
 * implements the clarified version:
 *
 *   "An authorised compliance officer can produce, for a stated time window, a complete and
 *    verifiable record of every read or export of client account data: who accessed what, when,
 *    and under what stated purpose - together with evidence that the underlying log has not
 *    been altered."
 *
 * Three design consequences follow from that sentence, and they are the whole module:
 *
 *   1. "Access" must be an *event* we record. A log that only holds writes cannot answer a
 *      question about reads, no matter how good the query API is. The taxonomy below is the
 *      contract producers must emit against.
 *   2. "Verifiable" means the report carries integrity evidence, not just rows. A regulator
 *      who cannot tell whether the source was tampered with has a spreadsheet, not evidence.
 *   3. Reading the report is itself an access to client data, so generating one appends its
 *      own audit event. Otherwise the surveillance surface is the one blind spot in the log.
 */

import { narrowFilters, type AccessScope } from '../domain/access-scope.js';
import { AppError } from '../domain/errors.js';
import type { StoredRecord } from '../domain/record.js';
import type { AuditRepository, QueryFilters } from '../storage/repository.js';
import { AuditService, SYSTEM_EVENT_TYPES } from './audit-service.js';
import type { VerificationReport } from './verification.js';

/**
 * What counts as "client account data", and what counts as "access".
 *
 * This is configuration masquerading as code in a prototype: in production it belongs in a
 * data-classification registry owned by the privacy office, not in a source file. It is
 * enumerated here so the scope of the report is explicit and reviewable rather than implied.
 */
export const CLIENT_DATA_RESOURCE_TYPES = [
  'client_account',
  'client_profile',
  'client_position',
  'client_statement',
  'client_tax_document',
] as const;

export const ACCESS_EVENT_TYPES = [
  'RECORD_VIEWED',
  'RECORD_EXPORTED',
  'RECORD_SEARCHED',
  'REPORT_GENERATED',
  'PERMISSION_GRANTED',
  'PERMISSION_REVOKED',
] as const;

export interface AccessReportCriteria {
  from: string;
  to: string;
  /** Narrow to a single client, which is the common regulator request ("show me this client"). */
  clientId?: string;
  /** Narrow to a single actor, the other common request ("show me this employee"). */
  actorId?: string;
  limit?: number;
  cursor?: string;
}

export interface AccessReportEntry {
  eventId: string;
  seq: number;
  occurredAt: string;
  recordedAt: string;
  eventType: string;
  actorId: string;
  resourceType: string;
  resourceId: string;
  /** Purpose-of-access, if the producer supplied one. Absence is itself a compliance finding. */
  statedPurpose: string | null;
  lifecycleState: string;
  recordHash: string;
}

export interface AccessReport {
  reportId: string;
  generatedAt: string;
  generatedBy: string;
  criteria: AccessReportCriteria;
  scope: {
    clientDataResourceTypes: readonly string[];
    accessEventTypes: readonly string[];
  };
  summary: {
    totalEvents: number;
    distinctActors: number;
    distinctClients: number;
    byEventType: Record<string, number>;
    /** Access events with no stated purpose: the finding a regulator is usually looking for. */
    eventsWithoutStatedPurpose: number;
  };
  entries: AccessReportEntry[];
  nextCursor: string | null;
  /**
   * Integrity evidence. Without this the report is a spreadsheet; with it, the recipient can
   * see that the records it summarises sit in a chain that verified clean at generation time.
   */
  integrity: {
    chainVerified: boolean;
    verification: VerificationReport;
    chainHead: { seq: number; recordHash: string };
  };
}

export class ComplianceService {
  constructor(
    private readonly repo: AuditRepository,
    private readonly audit: AuditService,
    private readonly now: () => Date = () => new Date(),
  ) {}

  generateAccessReport(
    criteria: AccessReportCriteria,
    generatedBy: string,
    scope?: AccessScope,
  ): AccessReport {
    const from = new Date(criteria.from);
    const to = new Date(criteria.to);
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
      throw AppError.validation('from and to must be valid ISO-8601 date-times');
    }
    if (from >= to) throw AppError.validation('from must be strictly earlier than to');

    // Archived records are included: a regulator asking about a historical window must see that
    // an access happened even when the payload detail is gone. Omitting them would understate
    // access, which is the opposite of what a compliance report is for.
    const filters: QueryFilters = {
      from: from.toISOString(),
      to: to.toISOString(),
      includeArchived: true,
    };
    if (criteria.actorId !== undefined) filters.actorId = criteria.actorId;
    if (criteria.clientId !== undefined) filters.resourceId = criteria.clientId;

    // A compliance report is exactly the endpoint an over-broad credential would be used to
    // sweep the whole log, so object-level scope is applied here too rather than trusted to the
    // role check.
    const matching = this.collect(narrowFilters(filters, scope));

    const limit = Math.min(criteria.limit ?? 100, 1000);
    const cursor = criteria.cursor === undefined ? 0 : Number(criteria.cursor);
    if (!Number.isInteger(cursor) || cursor < 0) {
      throw AppError.validation('cursor must be a non-negative integer returned by a prior page');
    }
    const window = matching.filter((record) => record.seq > cursor);
    const page = window.slice(0, limit);
    const hasMore = window.length > limit;

    const entries = page.map(toEntry);
    const verification = this.audit.verify();

    const report: AccessReport = {
      reportId: `access-${this.now().getTime()}`,
      generatedAt: this.now().toISOString(),
      generatedBy,
      criteria,
      scope: {
        clientDataResourceTypes: CLIENT_DATA_RESOURCE_TYPES,
        accessEventTypes: ACCESS_EVENT_TYPES,
      },
      summary: {
        totalEvents: matching.length,
        distinctActors: new Set(matching.map((record) => record.actorId)).size,
        distinctClients: new Set(matching.map((record) => record.resourceId)).size,
        byEventType: tally(matching.map((record) => record.eventType)),
        eventsWithoutStatedPurpose: matching.filter((record) => statedPurpose(record) === null)
          .length,
      },
      entries,
      nextCursor: hasMore ? String(page[page.length - 1]?.seq) : null,
      integrity: {
        chainVerified: verification.intact,
        verification,
        chainHead: this.audit.tip(),
      },
    };

    // Generating the report is itself an access to client data. Recording it closes the loop:
    // the people auditing the log are audited by it too.
    this.audit.append({
      eventType: SYSTEM_EVENT_TYPES.report,
      actorId: generatedBy,
      resourceType: 'compliance_report',
      resourceId: report.reportId,
      payload: {
        criteria: { ...criteria },
        matchedEvents: matching.length,
        returnedEvents: entries.length,
        chainVerifiedAtGeneration: verification.intact,
      },
    });

    return report;
  }

  /** Page through the store, keeping only client-data access events. */
  private collect(filters: QueryFilters): StoredRecord[] {
    const resourceTypes = new Set<string>(CLIENT_DATA_RESOURCE_TYPES);
    const eventTypes = new Set<string>(ACCESS_EVENT_TYPES);
    const results: StoredRecord[] = [];
    let cursor: number | undefined;

    for (;;) {
      const page = this.repo.query(filters, 500, cursor);
      for (const record of page.items) {
        if (resourceTypes.has(record.resourceType) && eventTypes.has(record.eventType)) {
          results.push(record);
        }
      }
      if (page.nextCursor === null) return results;
      cursor = Number(page.nextCursor);
    }
  }
}

/**
 * Purpose-of-access is read from a conventional payload field. A record that lacks one is
 * reported rather than dropped: "we cannot show why this employee opened this client's account"
 * is exactly the answer a regulator needs to hear, and hiding it would be the real failure.
 */
function statedPurpose(record: StoredRecord): string | null {
  const payload = record.payload;
  if (payload === null) return null;
  const value = payload.purpose ?? payload.reason ?? payload.justification;
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

function toEntry(record: StoredRecord): AccessReportEntry {
  return {
    eventId: record.eventId,
    seq: record.seq,
    occurredAt: record.occurredAt,
    recordedAt: record.recordedAt,
    eventType: record.eventType,
    actorId: record.actorId,
    resourceType: record.resourceType,
    resourceId: record.resourceId,
    statedPurpose: statedPurpose(record),
    lifecycleState: record.lifecycleState,
    recordHash: record.recordHash,
  };
}

function tally(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}
