#!/usr/bin/env bash
#
# End-to-end demonstration, following the validation procedure the brief specifies:
#
#   "write events, query them, verify the chain, then modify a record directly in the data
#    store and verify again to confirm detection"
#
# ...and then the Scenario B and C features on top. Everything runs over real HTTP against a
# real server with a real SQLite file. The tamper step uses the sqlite3 CLI, not our API.
#
#   ./scripts/demo.sh
#
set -euo pipefail

PORT="${PORT:-3999}"
DB="./data/demo-$$.db"
BASE="http://127.0.0.1:${PORT}"
WRITER="X-API-Key: dev-writer-key"
READER="X-API-Key: dev-reader-key"
AUDITOR="X-API-Key: dev-auditor-key"
ADMIN="X-API-Key: dev-admin-key"

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
note() { printf '  \033[2m%s\033[0m\n' "$1"; }

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
  rm -f "${DB}" "${DB}-wal" "${DB}-shm" ./demo-bundle.json
}
trap cleanup EXIT

command -v jq >/dev/null || { echo "This demo needs jq (brew install jq)"; exit 1; }
command -v sqlite3 >/dev/null || { echo "This demo needs the sqlite3 CLI"; exit 1; }

bold "0. Starting the service on a fresh database"
rm -f "${DB}"
PORT="${PORT}" DATABASE_PATH="${DB}" LOG_LEVEL=error npx tsx src/index.ts &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf "${BASE}/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -s "${BASE}/health" | jq -c .

write_event() {
  curl -s -X POST "${BASE}/audit/events" -H "${WRITER}" -H 'Content-Type: application/json' \
    -d "$1"
}

bold "1. SCENARIO A - Write events"
FIRST=$(write_event '{
  "eventType":"USER_LOGIN","actorId":"advisor-7",
  "resourceType":"session","resourceId":"sess-1",
  "payload":{"ip":"198.51.100.4","mfa":true}
}')
echo "${FIRST}" | jq -c '{seq, eventType, recordHash, prevHash}'
note "prevHash is the genesis value: this is the first link in the chain."

SENSITIVE=$(write_event '{
  "eventType":"RECORD_VIEWED","actorId":"advisor-7",
  "resourceType":"client_account","resourceId":"client-100",
  "payload":{"purpose":"Servicing call SR-4471","account":{"number":"123456789","holder":"A. Client"},"ssn":"555-01-0001"}
}')
SENSITIVE_ID=$(echo "${SENSITIVE}" | jq -r .eventId)
echo "${SENSITIVE}" | jq -c '{seq, eventType, recordHash}'

write_event '{"eventType":"RECORD_EXPORTED","actorId":"advisor-7","resourceType":"client_statement","resourceId":"client-100","payload":{"purpose":"Client requested copy"}}' >/dev/null
write_event '{"eventType":"RECORD_VIEWED","actorId":"analyst-2","resourceType":"client_position","resourceId":"client-200","payload":{"note":"no purpose recorded"}}' >/dev/null
write_event '{"eventType":"PERMISSION_GRANTED","actorId":"admin-1","resourceType":"client_account","resourceId":"client-100","payload":{"grantee":"advisor-9","level":"read"}}' >/dev/null
note "5 events written; each links to the digest of the one before it."

bold "2. SCENARIO A - Query with filters and pagination"
curl -s "${BASE}/audit/events?actorId=advisor-7&limit=2" -H "${READER}" \
  | jq -c '{returned: (.items|length), nextCursor, actors: [.items[].actorId]}'
curl -s "${BASE}/audit/events?resourceType=client_account&resourceId=client-100" -H "${READER}" \
  | jq -c '{matched: (.items|length), types: [.items[].eventType]}'

bold "3. SCENARIO A - Append-only is enforced, not just documented"
curl -s -o /dev/null -w '  DELETE /audit/events/<id> -> HTTP %{http_code}\n' \
  -X DELETE "${BASE}/audit/events/${SENSITIVE_ID}" -H "${ADMIN}"
curl -s -X PATCH "${BASE}/audit/events/${SENSITIVE_ID}" -H "${ADMIN}" | jq -r '"  " + .error.message'

bold "4. SCENARIO A - Verify the chain (expect: intact)"
curl -s "${BASE}/audit/verify" -H "${AUDITOR}" | jq -c '{intact, recordsChecked, firstViolation}'

bold "5. SCENARIO A - TAMPER DIRECTLY IN THE DATA STORE"
note "Bypassing the API entirely, as an attacker with database access would."
note "The schema triggers block this, so the demo drops them first - which is exactly the"
note "threat model: triggers stop accidents, the hash chain catches deliberate tampering."
sqlite3 "${DB}" "DROP TRIGGER IF EXISTS audit_events_immutable_update;"
sqlite3 "${DB}" "UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 3;"
note "Changed the actor on record 3 from 'advisor-7' to 'someone-else'."

bold "6. SCENARIO A - Verify again (expect: BREAK DETECTED at seq 3)"
curl -s "${BASE}/audit/verify" -H "${AUDITOR}" \
  | jq '{intact, totalViolations, firstViolation: {seq: .firstViolation.seq, type: .firstViolation.type, message: .firstViolation.message}}'
note "Records 1-2 remain trustworthy. Everything from 3 onward is suspect."

bold "7. Restarting on a clean database for Scenarios B and C"
kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
rm -f "${DB}" "${DB}-wal" "${DB}-shm"
PORT="${PORT}" DATABASE_PATH="${DB}" LOG_LEVEL=error npx tsx src/index.ts &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -sf "${BASE}/health" >/dev/null 2>&1 && break; sleep 0.2; done

SENSITIVE=$(write_event '{
  "eventType":"RECORD_VIEWED","actorId":"advisor-7",
  "resourceType":"client_account","resourceId":"client-100",
  "payload":{"purpose":"Servicing call SR-4471","account":{"number":"123456789","holder":"A. Client"},"ssn":"555-01-0001"}
}')
SENSITIVE_ID=$(echo "${SENSITIVE}" | jq -r .eventId)
HASH_BEFORE=$(echo "${SENSITIVE}" | jq -r .recordHash)
write_event '{"eventType":"RECORD_EXPORTED","actorId":"advisor-7","resourceType":"client_statement","resourceId":"client-100","payload":{"purpose":"Client requested copy"}}' >/dev/null
write_event '{"eventType":"RECORD_VIEWED","actorId":"analyst-2","resourceType":"client_position","resourceId":"client-200","payload":{"note":"no purpose recorded"}}' >/dev/null

bold "8. SCENARIO B - Redact sensitive fields WITHOUT breaking the chain"
note "record hash before redaction: ${HASH_BEFORE}"
curl -s -X POST "${BASE}/audit/events/${SENSITIVE_ID}/redactions" -H "${ADMIN}" \
  -H 'Content-Type: application/json' \
  -d '{"paths":["account.number","ssn"],"reason":"Data subject erasure request DSR-2026-118"}' \
  | jq -c '{payload, redactions: [.redactions[].path], recordHash}'
HASH_AFTER=$(curl -s "${BASE}/audit/events/${SENSITIVE_ID}" -H "${READER}" | jq -r .recordHash)
note "record hash after  redaction: ${HASH_AFTER}"
if [[ "${HASH_BEFORE}" == "${HASH_AFTER}" ]]; then
  printf '  \033[32mIDENTICAL - the values are gone and the chain is untouched.\033[0m\n'
else
  printf '  \033[31mMISMATCH - the redaction scheme is broken.\033[0m\n'; exit 1
fi
curl -s "${BASE}/audit/verify" -H "${AUDITOR}" | jq -c '{intact, recordsChecked}'
note "The redaction appended its own PAYLOAD_REDACTED event: the log records its own erasures."

bold "9. SCENARIO C - Regulator-facing client data access report"
curl -s "${BASE}/audit/reports/client-data-access?from=2000-01-01T00:00:00.000Z&to=2099-01-01T00:00:00.000Z" \
  -H "${AUDITOR}" \
  | jq '{summary, integrity: {chainVerified: .integrity.chainVerified, head: .integrity.chainHead.seq}, entries: [.entries[] | {actorId, eventType, resourceId, statedPurpose}]}'
note "eventsWithoutStatedPurpose is the finding a regulator is looking for."
note "Generating this report appended a COMPLIANCE_REPORT_GENERATED event: the auditors are audited."

bold "10. SCENARIO B - Apply retention (archive) and verify there is NO false break"
curl -s -X POST "${BASE}/audit/retention/apply" -H "${ADMIN}" -H 'Content-Type: application/json' \
  -d '{"windowDays":0}' | jq -c '{archivedCount, cutoff}'
curl -s "${BASE}/audit/verify" -H "${AUDITOR}" | jq -c '{intact, recordsChecked, firstViolation}'
note "Archived records keep their full hash skeleton, so verification needs no exception."

bold "11. SCENARIO C - The same report after archival"
curl -s "${BASE}/audit/reports/client-data-access?from=2000-01-01T00:00:00.000Z&to=2099-01-01T00:00:00.000Z" \
  -H "${AUDITOR}" \
  | jq -c '{totalEvents: .summary.totalEvents, withoutPurpose: .summary.eventsWithoutStatedPurpose, lifecycles: [.entries[].lifecycleState]}'
note "The accesses are still reported - a historical window must not understate access."
note "But their stated purposes are gone with the payloads. That is the real cost of a"
note "retention policy, and the report shows it rather than hiding it."

bold "12. SCENARIO B - Export a verifiable bundle and check it OFFLINE"
curl -s "${BASE}/audit/export?resourceId=client-100" -H "${AUDITOR}" > demo-bundle.json
jq -c '{records: (.records|length), bundleHash, globalHead: .chainContext.globalChainHead.seq}' demo-bundle.json
npx tsx src/cli/verify-bundle.ts demo-bundle.json

bold "13. SCENARIO B - Tamper with the exported bundle and re-check"
jq '.records[0].actorId = "attacker"' demo-bundle.json > demo-bundle-tampered.json
mv demo-bundle-tampered.json demo-bundle.json
npx tsx src/cli/verify-bundle.ts demo-bundle.json || true

bold "Demo complete."
