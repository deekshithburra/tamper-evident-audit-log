/**
 * Crash-simulation harness.
 *
 * Run as a child process by `tests/integration/crash-recovery.test.ts` and by
 * `scripts/demo.sh`. It opens the real repository against a real file database, appends events
 * through the real service, and prints one line per *acknowledged* write:
 *
 *     ACK <seq> <recordHash>
 *
 * The parent kills it with SIGKILL partway through - no signal handler, no flush, no graceful
 * close, the way a power loss or an OOM kill actually behaves. The parent then reopens the
 * database and asserts two things that matter more than any unit test:
 *
 *   1. Durability - every seq this process acknowledged is still there. A store that
 *      acknowledges a write it can lose is lying to its caller, and for an audit log that is
 *      the difference between evidence and decoration.
 *   2. Integrity - the chain still verifies. A write torn halfway through must leave no
 *      partial record behind, or recovery would look identical to tampering.
 *
 * Usage: tsx scripts/crash-writer.ts <databasePath> [totalWrites]
 */

import { loadConfig } from '../src/config.js';
import { AuditRepository } from '../src/storage/repository.js';
import { AuditService } from '../src/services/audit-service.js';

const databasePath = process.argv[2];
const total = Number(process.argv[3] ?? 500);

if (databasePath === undefined) {
  console.error('Usage: tsx scripts/crash-writer.ts <databasePath> [totalWrites]');
  process.exit(2);
}

const config = loadConfig({
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  DATABASE_PATH: databasePath,
  API_KEYS: 'crash-writer-key:writer',
});

const repo = new AuditRepository(databasePath);
const service = new AuditService(repo, config);

// Deliberately no SIGTERM/SIGINT handler and no cleanup on exit: this process is meant to die
// abruptly. Anything that flushed on the way out would weaken the test.
for (let i = 0; i < total; i += 1) {
  const record = service.append({
    eventType: 'RECORD_UPDATED',
    actorId: `crash-actor-${i % 5}`,
    resourceType: 'client_account',
    resourceId: `acct-${i}`,
    payload: { index: i, note: `write ${i}`, nested: { detail: `d-${i}` } },
  });

  // Acknowledge only after the transaction has committed, which is exactly the promise the
  // HTTP 201 makes to a caller.
  process.stdout.write(`ACK ${record.seq} ${record.recordHash}\n`);
}

process.stdout.write('DONE\n');
