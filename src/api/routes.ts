/**
 * HTTP surface.
 *
 * The shape of this file is itself part of the append-only guarantee (ADR-0002, layer 1):
 * there is no PUT, PATCH or DELETE on an audit record anywhere below, and the explicit 405
 * handler makes that a documented refusal rather than something a caller has to infer from a
 * 404.
 */

import { Router, type Request, type Response } from 'express';
import { AppError } from '../domain/errors.js';
import type { StoredRecord } from '../domain/record.js';
import { CAPABILITIES, authenticate, requireCapability } from './auth.js';
import { rateLimit, type RateLimiter } from './rate-limit.js';
import { describeScope } from '../domain/access-scope.js';
import type { CredentialStore } from './credentials.js';
import {
  accessReportSchema,
  exportSchema,
  queryEventsSchema,
  redactionSchema,
  retentionSchema,
  verifySchema,
  writeEventSchema,
} from './schemas.js';
import type { AuditService } from '../services/audit-service.js';
import type { ComplianceService } from '../services/compliance-service.js';
import type { Config } from '../config.js';

/**
 * Public projection of a record.
 *
 * Salts are withheld: they are the hiding factor for the field commitments, and publishing
 * them would let anyone brute-force a low-entropy field value from its leaf digest - the exact
 * attack the salts exist to prevent. Leaf digests are exposed, because a verifier needs them.
 */
export function present(record: StoredRecord) {
  return {
    eventId: record.eventId,
    seq: record.seq,
    eventType: record.eventType,
    actorId: record.actorId,
    resourceType: record.resourceType,
    resourceId: record.resourceId,
    occurredAt: record.occurredAt,
    recordedAt: record.recordedAt,
    payload: record.payload,
    payloadRoot: record.payloadRoot,
    prevHash: record.prevHash,
    recordHash: record.recordHash,
    alg: record.alg,
    lifecycleState: record.lifecycleState,
    archivedAt: record.archivedAt,
    redactions: record.redactions,
  };
}

/**
 * Export projection. Unlike `present`, this includes the leaf digests *and their salts*.
 *
 * That is safe and necessary, not a leak: the recipient of an export already holds the
 * plaintext of every non-redacted field, so its salt reveals nothing new - while without it
 * they could only accept the stored leaf digests on faith rather than re-deriving them. The
 * salts that actually matter, for redacted and archived fields, were destroyed at redaction
 * time and cannot appear here.
 */
export function presentForExport(record: StoredRecord) {
  return { ...present(record), leaves: record.leaves, salts: record.salts };
}

export function buildRoutes(deps: {
  config: Config;
  audit: AuditService;
  compliance: ComplianceService;
  credentials: CredentialStore;
  limiter: RateLimiter;
}): Router {
  const router = Router();
  const { audit, compliance, limiter } = deps;

  // Cost classes are declared at the point each route is defined, so the budget a call consumes
  // is visible when reading the router rather than buried in the limiter.
  const cheapWrite = rateLimit(limiter, 'write');
  const cheapRead = rateLimit(limiter, 'read');
  const expensive = rateLimit(limiter, 'expensive');

  router.get('/health', (_req: Request, res: Response) => {
    const tip = audit.tip();
    res.json({ status: 'ok', records: audit.count(), chainHead: tip.recordHash, headSeq: tip.seq });
  });

  router.use(authenticate(deps.config, deps.credentials));

  // ------------------------------------------------------------------ identity & credentials

  /** What am I, and what may I reach? Lets a client verify its own scope and expiry. */
  router.get('/auth/whoami', requireCapability('identity:read'), (req: Request, res: Response) => {
    const principal = req.principal;
    res.json({
      id: principal?.id,
      role: principal?.role,
      capabilities: principal === undefined ? [] : CAPABILITIES[principal.role],
      scope: describeScope(principal?.scope),
      expiresAt: principal?.expiresAt ?? null,
    });
  });

  /**
   * Credential inventory: state, expiry and rotation pressure. Secrets are never included.
   * Answers "which keys are about to lapse" without anyone reading deployment config.
   */
  router.get(
    '/auth/credentials',
    requireCapability('credentials:read'),
    (_req: Request, res: Response) => {
      const inventory = deps.credentials.inventory(
        new Date(),
        deps.config.credentialRotationWarningDays,
      );
      res.json({
        credentials: inventory,
        rotationDue: inventory.filter((entry) => entry.rotationDue).map((entry) => entry.id),
        policy: {
          rotationWarningDays: deps.config.credentialRotationWarningDays,
          maxLifetimeDays: deps.config.maxCredentialLifetimeDays,
          nonExpiringPermitted: deps.config.env !== 'production',
        },
      });
    },
  );

  // ------------------------------------------------------------------ Scenario A: write

  router.post('/audit/events', requireCapability('events:write'), cheapWrite, (req: Request, res: Response) => {
    const input = writeEventSchema.parse(req.body);
    const record = audit.append(input);
    res.status(201).json(present(record));
  });

  // Append-only, enforced and *explained* at the edge (ADR-0002, layer 1).
  const appendOnly = (_req: Request, res: Response): void => {
    res.set('Allow', 'GET, POST');
    res.status(405).json({
      error: {
        code: 'METHOD_NOT_ALLOWED',
        message:
          'Audit records are append-only. They cannot be updated or deleted. ' +
          'To correct a record, append a compensating event; to erase sensitive payload ' +
          'fields, use POST /audit/events/:eventId/redactions.',
      },
    });
  };
  router.put(['/audit/events', '/audit/events/:eventId'], appendOnly);
  router.patch(['/audit/events', '/audit/events/:eventId'], appendOnly);
  router.delete(['/audit/events', '/audit/events/:eventId'], appendOnly);

  // ------------------------------------------------------------------ Scenario A: query

  router.get('/audit/events', requireCapability('events:read'), cheapRead, (req: Request, res: Response) => {
    const params = queryEventsSchema.parse(req.query);
    const page = audit.query(
      {
        ...(params.actorId === undefined ? {} : { actorId: params.actorId }),
        ...(params.resourceType === undefined ? {} : { resourceType: params.resourceType }),
        ...(params.resourceId === undefined ? {} : { resourceId: params.resourceId }),
        ...(params.eventType === undefined ? {} : { eventType: params.eventType }),
        ...(params.from === undefined ? {} : { from: params.from }),
        ...(params.to === undefined ? {} : { to: params.to }),
        ...(params.includeArchived === undefined ? {} : { includeArchived: params.includeArchived }),
      },
      params.limit,
      params.cursor,
      req.principal?.scope,
    );
    res.json({
      items: page.items.map(present),
      nextCursor: page.nextCursor,
      pageSize: page.items.length,
    });
  });

  router.get(
    '/audit/events/:eventId',
    requireCapability('events:read'),
    cheapRead,
    (req: Request, res: Response) => {
      res.json(present(audit.getByEventId(req.params.eventId as string, req.principal?.scope)));
    },
  );

  // ------------------------------------------------------------------ Scenario A: verification

  router.get('/audit/verify', requireCapability('chain:verify'), expensive, (req: Request, res: Response) => {
    const params = verifySchema.parse(req.query);
    const report = audit.verify(params.fromSeq === undefined ? {} : { fromSeq: params.fromSeq });
    // 200 for an intact chain, 409 for a broken one: a monitoring probe should alarm on the
    // status code without having to parse a body, and a broken chain is a conflict between what
    // the store claims and what the cryptography proves.
    res.status(report.intact ? 200 : 409).json(report);
  });

  // ------------------------------------------------------------------ Scenario B: retention

  router.post(
    '/audit/retention/apply',
    requireCapability('retention:apply'),
    expensive,
    (req: Request, res: Response) => {
      const params = retentionSchema.parse(req.body ?? {});
      const result = audit.applyRetention({
        ...(params.windowDays === undefined ? {} : { windowDays: params.windowDays }),
        ...(params.limit === undefined ? {} : { limit: params.limit }),
        appliedBy: req.principal?.id ?? 'unknown',
      });
      res.json(result);
    },
  );

  // ------------------------------------------------------------------ Scenario B: redaction

  router.post(
    '/audit/events/:eventId/redactions',
    requireCapability('records:redact'),
    cheapWrite,
    (req: Request, res: Response) => {
      const body = redactionSchema.parse(req.body);
      const record = audit.redact({
        eventId: req.params.eventId as string,
        paths: body.paths,
        reason: body.reason,
        requestedBy: req.principal?.id ?? 'unknown',
        ...(req.principal?.scope === undefined ? {} : { scope: req.principal.scope }),
      });
      res.json(present(record));
    },
  );

  // ------------------------------------------------------------------ Scenario B: export

  router.get('/audit/export', requireCapability('records:export'), expensive, (req: Request, res: Response) => {
    const params = exportSchema.parse(req.query);
    const bundle = audit.exportBundle({
      ...(params.actorId === undefined ? {} : { actorId: params.actorId }),
      ...(params.resourceType === undefined ? {} : { resourceType: params.resourceType }),
      ...(params.resourceId === undefined ? {} : { resourceId: params.resourceId }),
    }, req.principal?.scope);
    res.json({ ...bundle, records: bundle.records.map(presentForExport) });
  });

  // ------------------------------------------------------------------ Scenario C: compliance

  router.get(
    '/audit/reports/client-data-access',
    requireCapability('reports:read'),
    expensive,
    (req: Request, res: Response) => {
      const params = accessReportSchema.parse(req.query);
      const report = compliance.generateAccessReport(
        params,
        req.principal?.id ?? 'unknown',
        req.principal?.scope,
      );
      res.json(report);
    },
  );

  router.all('/audit/*', (req: Request, _res: Response) => {
    throw AppError.notFound(`No route for ${req.method} ${req.path}`);
  });

  return router;
}
