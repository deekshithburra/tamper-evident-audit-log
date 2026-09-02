#!/usr/bin/env bash
#
# Crash simulation, visible.
#
# The crash-recovery test suite proves this automatically; this script is the version you can
# watch. It writes to a real database, kills the writer with SIGKILL - no handler, no flush, no
# graceful close, the way a power cut or an OOM kill actually behaves - then reopens the file
# and checks two things:
#
#   Durability  every write the process acknowledged is still there.
#   Integrity   the chain verifies, with no torn record left behind.
#
#   ./scripts/crash-demo.sh
#
set -euo pipefail

DB="./data/crash-demo-$$.db"
# Enough writes that the kill lands mid-stream rather than after the writer has finished.
WRITES=20000
KILL_AFTER=150

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
note() { printf '  \033[2m%s\033[0m\n' "$1"; }
good() { printf '  \033[32m%s\033[0m\n' "$1"; }
bad()  { printf '  \033[31m%s\033[0m\n' "$1"; }

cleanup() {
  [[ -n "${WRITER_PID:-}" ]] && kill -9 "${WRITER_PID}" 2>/dev/null || true
  rm -f "${DB}" "${DB}-wal" "${DB}-shm" /tmp/crash-acks-$$.txt
}
trap cleanup EXIT

mkdir -p ./data
rm -f "${DB}" "${DB}-wal" "${DB}-shm"

bold "1. Writing to a real database, acknowledging each committed record"
note "synchronous = FULL, so an acknowledgement means the record is on disk - not buffered."
# node is launched directly rather than through npx: npx would be the process we hold a PID
# for, and killing it leaves the real writer running - which silently turns this into a demo
# of nothing. (The automated suite spawns process.execPath for the same reason.)
node --import tsx scripts/crash-writer.ts "${DB}" "${WRITES}" > /tmp/crash-acks-$$.txt 2>/dev/null &
WRITER_PID=$!

# Wait until enough writes have been acknowledged, then pull the plug.
ack_count() {
  # grep -c prints 0 and exits 1 when nothing matches; `|| true` keeps `set -e` happy without
  # emitting a second count.
  ( grep -c '^ACK ' "/tmp/crash-acks-$$.txt" 2>/dev/null || true ) | head -1
}

for _ in $(seq 1 400); do
  ACKED=$(ack_count)
  [[ "${ACKED:-0}" -ge "${KILL_AFTER}" ]] && break
  sleep 0.05
done

bold "2. SIGKILL - no cleanup, no flush, no graceful close"
kill -9 "${WRITER_PID}" 2>/dev/null || true
wait "${WRITER_PID}" 2>/dev/null || true
sleep 0.3

ACKED=$(ack_count)
LAST_ACK=$(grep '^ACK ' "/tmp/crash-acks-$$.txt" | tail -1 | awk '{print $2}')
note "The writer acknowledged ${ACKED} records before it was killed (last seq ${LAST_ACK})."
note "It was midway through a run of ${WRITES}: this is a kill during active writing, not after."

bold "3. Reopening the database and checking what survived"
node --import tsx --eval "
import { loadConfig } from './src/config.ts';
import { AuditRepository } from './src/storage/repository.ts';
import { AuditService } from './src/services/audit-service.ts';

const dbPath = '${DB}';
const lastAck = ${LAST_ACK};
const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', DATABASE_PATH: dbPath, API_KEYS: 'k:admin' });
const repo = new AuditRepository(dbPath);
const service = new AuditService(repo, config);

const surviving = repo.count();
const durable = repo.getBySeq(lastAck) !== null;
const report = service.verify();

console.log(JSON.stringify({
  acknowledgedThrough: lastAck,
  recordsOnDisk: surviving,
  lastAcknowledgedSurvived: durable,
  chainIntact: report.intact,
  recordsChecked: report.recordsChecked,
  firstViolation: report.firstViolation,
}, null, 2));

const appended = service.append({
  eventType: 'SERVICE_RECOVERED', actorId: 'operator',
  resourceType: 'audit_log', resourceId: 'chain',
  payload: { note: 'restarted after unclean shutdown' },
});
console.log('resumed at seq ' + appended.seq + ', linked to the surviving head: ' + (appended.prevHash === repo.getBySeq(appended.seq - 1).recordHash));
repo.close();
process.exit(durable && report.intact ? 0 : 1);
" && good "DURABLE and INTACT - no acknowledged write lost, no torn record, chain still verifies." \
  || { bad "FAILED - durability or integrity was violated."; exit 1; }

note "This is why synchronous = FULL is set rather than the WAL default of NORMAL:"
note "an audit log that acknowledges a write it can lose on power failure is lying to its caller."
