/**
 * Offline bundle verifier.
 *
 *   npm run verify:bundle -- ./bundle.json
 *
 * This is what makes "independently verifiable" a real claim rather than a slogan. It touches
 * no database, no configuration, and no service code - only the pure hashing primitives, which
 * a recipient could equally re-implement in fifty lines of Python from `docs/ARCHITECTURE.md`.
 *
 * What it proves: every record's payload still matches its committed Merkle root, every record
 * hash matches its own contents, and the bundle itself has not been altered since export.
 * What it cannot prove, and says so: that the slice is *complete*. A filtered export is not a
 * contiguous chain, so absence of a record cannot be detected from the bundle alone - that
 * requires checking the included global chain head against the source, and the report prints
 * the exact command to do it.
 */

import { readFileSync } from 'node:fs';
import { recomputeRoot } from '../domain/commitments.js';
import { computeRecordHash, coreOf, type StoredRecord } from '../domain/record.js';
import { computeBundleHash, type ExportBundle } from '../services/audit-service.js';

interface Finding {
  seq: number;
  eventId: string;
  problem: string;
  expected?: string;
  actual?: string;
}

export function verifyBundle(bundle: ExportBundle): {
  ok: boolean;
  findings: Finding[];
  recordsChecked: number;
  bundleHashValid: boolean;
} {
  const findings: Finding[] = [];

  const { bundleHash, ...rest } = bundle;
  const recomputedBundleHash = computeBundleHash(rest);
  const bundleHashValid = recomputedBundleHash === bundleHash;
  if (!bundleHashValid) {
    findings.push({
      seq: -1,
      eventId: '-',
      problem: 'Bundle hash does not match its contents: the bundle was altered after export',
      expected: recomputedBundleHash,
      actual: bundleHash,
    });
  }

  for (const record of bundle.records as StoredRecord[]) {
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: record.leaves ?? [],
      salts: record.salts ?? {},
      payload: record.payload,
    });
    if (root !== record.payloadRoot) {
      findings.push({
        seq: record.seq,
        eventId: record.eventId,
        problem: `Payload does not match its committed root (fields: ${
          mismatchedPaths.join(', ') || 'unknown'
        })`,
        expected: record.payloadRoot,
        actual: root,
      });
    }

    const recomputed = computeRecordHash(coreOf(record));
    if (recomputed !== record.recordHash) {
      findings.push({
        seq: record.seq,
        eventId: record.eventId,
        problem: 'Record hash does not match the record contents',
        expected: recomputed,
        actual: record.recordHash,
      });
    }

    if (!bundle.chainContext.exportedSeqs.includes(record.seq)) {
      findings.push({
        seq: record.seq,
        eventId: record.eventId,
        problem: 'Record is not listed in the bundle manifest: it was inserted after export',
      });
    }
  }

  const manifestCount = bundle.chainContext.exportedSeqs.length;
  if (manifestCount !== bundle.records.length) {
    findings.push({
      seq: -1,
      eventId: '-',
      problem: 'Bundle manifest and record count disagree: records were added or removed',
      expected: String(manifestCount),
      actual: String(bundle.records.length),
    });
  }

  return {
    ok: findings.length === 0,
    findings,
    recordsChecked: bundle.records.length,
    bundleHashValid,
  };
}

function main(): void {
  const path = process.argv[2];
  if (path === undefined) {
    console.error('Usage: npm run verify:bundle -- <bundle.json>');
    process.exit(2);
  }

  const bundle = JSON.parse(readFileSync(path, 'utf8')) as ExportBundle;
  const result = verifyBundle(bundle);

  console.log(`Bundle:            ${path}`);
  console.log(`Subject:           ${bundle.subject.type} "${bundle.subject.id}"`);
  console.log(`Generated:         ${bundle.generatedAt}`);
  console.log(`Records checked:   ${result.recordsChecked}`);
  console.log(`Bundle hash:       ${result.bundleHashValid ? 'VALID' : 'INVALID'}`);
  console.log('');

  if (result.ok) {
    console.log('RESULT: VERIFIED');
    console.log('Every record in this bundle matches its cryptographic commitments.');
    console.log('');
    console.log('Completeness is NOT established by this check. To confirm no record was omitted,');
    console.log('compare the chain head below against the source service:');
    console.log(
      `  head seq ${bundle.chainContext.globalChainHead.seq} = ${bundle.chainContext.globalChainHead.recordHash}`,
    );
    process.exit(0);
  }

  console.log('RESULT: FAILED');
  for (const finding of result.findings) {
    console.log(`  [seq ${finding.seq}] ${finding.problem}`);
    if (finding.expected !== undefined) console.log(`      expected: ${finding.expected}`);
    if (finding.actual !== undefined) console.log(`      actual:   ${finding.actual}`);
  }
  process.exit(1);
}

// Run only when invoked directly, so the verification logic stays importable by tests.
if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split('/').pop() ?? '')) {
  main();
}
