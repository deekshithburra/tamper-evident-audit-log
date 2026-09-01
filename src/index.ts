/**
 * Server entrypoint.
 *
 * On startup the chain is verified once. If the store was tampered with while the service was
 * down, the operator finds out at boot rather than the next time somebody happens to call
 * /audit/verify. The service still starts - refusing to start would mean a tamper becomes a
 * denial of service, and it would also stop the log recording the incident response.
 */

import { createApplication } from './app.js';

const application = createApplication();
const { app, config, audit, logger } = application;

const startupReport = audit.verify();
if (startupReport.intact) {
  logger.info(
    { records: startupReport.recordsChecked, durationMs: startupReport.durationMs },
    'Chain verified at startup',
  );
} else {
  logger.error(
    { firstViolation: startupReport.firstViolation, totalViolations: startupReport.totalViolations },
    'CHAIN INTEGRITY FAILURE detected at startup: the audit store has been modified out of band',
  );
}

const server = app.listen(config.port, () => {
  logger.info({ port: config.port, database: config.databasePath }, 'Audit log service listening');
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    logger.info({ signal }, 'Shutting down');
    server.close(() => {
      application.close();
      process.exit(0);
    });
  });
}
