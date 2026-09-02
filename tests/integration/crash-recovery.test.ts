import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { AuditRepository } from '../../src/storage/repository.js';
import { AuditService } from '../../src/services/audit-service.js';

/**
 * Crash durability and recovery.
 *
 * Every other test in this suite runs against an in-memory database in a process that exits
 * cleanly, which proves nothing about what survives a power cut. These tests kill a real writer
 * process with SIGKILL - no handler, no flush, no graceful close - and then reopen the file.
 *
 * Two properties are asserted, and they pull in opposite directions:
 *
 *   Durability  every write the process ACKed is still present. `synchronous = FULL` is set
 *               precisely so an acknowledgement means "on disk", and this is the only test
 *               that actually checks that claim rather than restating it.
 *   Integrity   the chain verifies with no violations. A transaction torn in half must leave
 *               nothing behind, because a partial record is indistinguishable from tampering -
 *               and a system that cries tamper after every unclean shutdown is one nobody will
 *               believe when it matters.
 */
describe('crash recovery and durability', () => {
  let directory: string;
  let databasePath: string;
  let child: ChildProcessWithoutNullStreams | undefined;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'audit-crash-'));
    databasePath = join(directory, 'audit.db');
  });

  afterEach(() => {
    if (child !== undefined && child.exitCode === null) child.kill('SIGKILL');
    child = undefined;
    rmSync(directory, { recursive: true, force: true });
  });

  function reopen() {
    const config = loadConfig({
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      DATABASE_PATH: databasePath,
      API_KEYS: 'recovery-key:admin',
    });
    const repo = new AuditRepository(databasePath);
    return { repo, service: new AuditService(repo, config) };
  }

  /**
   * Start the writer, wait until it has acknowledged `killAfter` writes, then SIGKILL it.
   * Resolves with the sequence numbers it managed to acknowledge.
   */
  function crashDuringWrites(killAfter: number, total = 400): Promise<number[]> {
    return new Promise((resolve, reject) => {
      const acknowledged: number[] = [];
      child = spawn(
        process.execPath,
        ['--import', 'tsx', 'scripts/crash-writer.ts', databasePath, String(total)],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );

      let buffer = '';
      let killed = false;
      const timer = setTimeout(() => {
        child?.kill('SIGKILL');
        reject(new Error(`Writer never reached ${killAfter} acknowledged writes`));
      }, 30_000);

      child.stdout.on('data', (chunk: Buffer) => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';
        for (const line of lines) {
          const match = /^ACK (\d+) ([0-9a-f]{64})$/.exec(line);
          if (match !== null) acknowledged.push(Number(match[1]));
        }
        if (!killed && acknowledged.length >= killAfter) {
          killed = true;
          clearTimeout(timer);
          // SIGKILL: uncatchable. The process gets no chance to flush, close the database, or
          // run any cleanup - the same abruptness as a power loss or an OOM kill.
          child?.kill('SIGKILL');
          // Give the OS a moment to reap it before the parent reopens the file.
          setTimeout(() => resolve(acknowledged), 250);
        }
      });

      child.on('error', reject);
    });
  }

  it('preserves every acknowledged write across a SIGKILL', async () => {
    const acknowledged = await crashDuringWrites(60);
    expect(acknowledged.length).toBeGreaterThanOrEqual(60);

    const { repo, service } = reopen();
    try {
      const surviving = repo.count();
      // Durability: nothing acknowledged may be missing. The store may contain MORE than was
      // acknowledged - a write can commit after the ACK line was buffered but before the kill -
      // which is fine. Losing an acknowledged write is not.
      expect(surviving).toBeGreaterThanOrEqual(Math.max(...acknowledged));

      for (const seq of acknowledged) {
        expect(repo.getBySeq(seq), `acknowledged seq ${seq} was lost`).not.toBeNull();
      }

      const report = service.verify();
      expect(report.intact).toBe(true);
      expect(report.firstViolation).toBeNull();
    } finally {
      repo.close();
    }
  }, 45_000);

  it('leaves no torn record behind: the chain verifies after an unclean shutdown', async () => {
    await crashDuringWrites(120);

    const { repo, service } = reopen();
    try {
      const report = service.verify();
      expect(report.intact).toBe(true);
      expect(report.totalViolations).toBe(0);
      expect(report.recordsChecked).toBeGreaterThan(100);

      // Sequence numbers must be contiguous from 1: a half-written record that left a gap would
      // be reported as tampering by the verifier, and recovery must never look like an attack.
      const seqs: number[] = [];
      for (const record of repo.scan(1)) seqs.push(record.seq);
      expect(seqs).toEqual(Array.from({ length: seqs.length }, (_, i) => i + 1));
    } finally {
      repo.close();
    }
  }, 45_000);

  it('accepts new appends onto the recovered chain, linked to the surviving head', async () => {
    await crashDuringWrites(40);

    const { repo, service } = reopen();
    try {
      const headBefore = repo.tip();

      const appended = service.append({
        eventType: 'SERVICE_RECOVERED',
        actorId: 'operator',
        resourceType: 'audit_log',
        resourceId: 'chain',
        payload: { note: 'restarted after unclean shutdown' },
      });

      // The recovered chain continues rather than restarting: the new record links to the
      // record that survived the crash.
      expect(appended.prevHash).toBe(headBefore.recordHash);
      expect(appended.seq).toBe(headBefore.seq + 1);

      const report = service.verify();
      expect(report.intact).toBe(true);
    } finally {
      repo.close();
    }
  }, 45_000);

  it('survives two consecutive crashes without corrupting the chain', async () => {
    await crashDuringWrites(30);
    const afterFirst = (() => {
      const { repo } = reopen();
      const count = repo.count();
      repo.close();
      return count;
    })();

    await crashDuringWrites(30);

    const { repo, service } = reopen();
    try {
      expect(repo.count()).toBeGreaterThan(afterFirst);
      const report = service.verify();
      expect(report.intact).toBe(true);
      expect(report.firstViolation).toBeNull();
    } finally {
      repo.close();
    }
  }, 60_000);
});
