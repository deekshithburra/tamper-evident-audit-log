/**
 * Application composition root.
 *
 * Everything is constructed here and injected, so tests build a complete, isolated application
 * against an in-memory database in one call - no module-level singletons, no shared state
 * between test files, no cleanup fixtures.
 */

import express, { type Express } from 'express';
import pino, { type Logger } from 'pino';
import pinoHttp from 'pino-http';
import { loadConfig, type Config } from './config.js';
import { AuditRepository } from './storage/repository.js';
import { AuditService } from './services/audit-service.js';
import { ComplianceService } from './services/compliance-service.js';
import { buildRoutes } from './api/routes.js';
import { CredentialStore } from './api/credentials.js';
import { FixedWindowRateLimiter, UnlimitedRateLimiter, type RateLimiter } from './api/rate-limit.js';
import { errorHandler, notFoundHandler } from './api/error-handler.js';

export interface Application {
  app: Express;
  config: Config;
  repo: AuditRepository;
  audit: AuditService;
  compliance: ComplianceService;
  credentials: CredentialStore;
  limiter: RateLimiter;
  logger: Logger;
  close: () => void;
}

export interface ApplicationOptions {
  /** Injected so rate-limit tests can advance time instead of sleeping. */
  clock?: () => number;
  /** Override the limiter entirely (e.g. UnlimitedRateLimiter in unrelated suites). */
  limiter?: RateLimiter;
}

export function createApplication(
  overrides: Partial<Config> = {},
  env: NodeJS.ProcessEnv = process.env,
  options: ApplicationOptions = {},
): Application {
  const config = { ...loadConfig(env), ...overrides };

  const logger = pino({
    level: config.logLevel,
    // Payloads may contain client account data. Logging is not an audit trail, and the audit
    // trail is not a log: nothing here should ever hold a payload body or an API key.
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers["x-api-key"]',
        'req.body.payload',
        'res.body',
      ],
      censor: '[redacted]',
    },
  });

  const repo = new AuditRepository(config.databasePath);
  const audit = new AuditService(repo, config);
  const compliance = new ComplianceService(repo, audit);
  const credentials = new CredentialStore(config.credentials);
  const limiter =
    options.limiter ??
    (config.rateLimit.enabled
      ? new FixedWindowRateLimiter(config.rateLimit, options.clock)
      : new UnlimitedRateLimiter());

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);

  app.use(
    pinoHttp({
      logger,
      // Health checks would otherwise dominate the log and hide the requests that matter.
      autoLogging: { ignore: (req) => req.url === '/health' },
    }),
  );
  app.use(
    express.json({
      // Bounded well below the payload limit so an oversized body is rejected by the parser
      // before any hashing work is done on it.
      limit: '256kb',
      strict: true,
    }),
  );
  app.use(securityHeaders);

  app.use(buildRoutes({ config, audit, compliance, credentials, limiter }));
  app.use(notFoundHandler);
  app.use(errorHandler(logger));

  return {
    app,
    config,
    repo,
    audit,
    compliance,
    credentials,
    limiter,
    logger,
    close: () => repo.close(),
  };
}

/** This is a JSON API with no browser surface, so the headers simply close off what it never uses. */
function securityHeaders(_req: express.Request, res: express.Response, next: express.NextFunction): void {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Cache-Control', 'no-store');
  res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  next();
}
