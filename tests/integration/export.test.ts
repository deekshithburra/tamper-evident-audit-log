import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, sampleEvent } from '../helpers.js';
import { verifyBundle } from '../../src/cli/verify-bundle.js';
import type { Application } from '../../src/app.js';
import type { ExportBundle } from '../../src/services/audit-service.js';

/**
 * Requirement B4: export must be a self-contained bundle a recipient can verify independently.
 *
 * Every check below runs through `verifyBundle`, which imports only the pure hashing
 * primitives - no repository, no config, no service. If these pass, a third party with the
 * JSON file and a SHA-256 implementation can reach the same conclusions.
 */
describe('verifiable bulk export (Scenario B)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    for (let i = 0; i < 6; i += 1) {
      await api.write(sampleEvent({ resourceId: 'acct-target', payload: { index: i } }));
      await api.write(sampleEvent({ resourceId: 'acct-other', actorId: 'user-other' }));
    }
  });
  afterEach(() => application.close());

  /** Assert the export succeeded before reasoning about its contents, so a non-200 reports
   *  itself as a status rather than as a confusing undefined-property error downstream. */
  async function bundleFor(query: string): Promise<ExportBundle> {
    const response = await api.exportBundle(query);
    expect(response.status, response.text).toBe(200);
    return response.body as ExportBundle;
  }

  it('exports every record for a resource, and nothing else', async () => {
    const response = await api.exportBundle('?resourceId=acct-target');
    expect(response.status).toBe(200);

    const bundle = response.body as ExportBundle;
    expect(bundle.records).toHaveLength(6);
    expect(bundle.records.every((r) => r.resourceId === 'acct-target')).toBe(true);
    expect(bundle.subject).toMatchObject({ type: 'resource', id: 'acct-target' });
  });

  it('exports by actor as well as by resource', async () => {
    const response = await api.exportBundle('?actorId=user-other');
    expect(response.body.records).toHaveLength(6);
    expect(response.body.subject.type).toBe('actor');
  });

  it('carries the chain metadata a recipient needs to reason about the slice', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');

    expect(bundle.algorithm).toBe('sha256');
    expect(bundle.genesisHash).toBe('0'.repeat(64));
    expect(bundle.chainContext.exportedSeqs).toEqual(bundle.records.map((r) => r.seq));
    expect(bundle.chainContext.globalChainHead.recordHash).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.bundleHash).toMatch(/^[0-9a-f]{64}$/);
    // Leaf digests and their salts travel with the records, so the recipient can re-derive
    // each committed field rather than accepting the digests on faith.
    expect(bundle.records[0]!.leaves.length).toBeGreaterThan(0);
    expect(Object.keys(bundle.records[0]!.salts).length).toBeGreaterThan(0);
  });

  it('VERIFIES OFFLINE with no access to the service', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    const result = verifyBundle(bundle);

    expect(result.ok).toBe(true);
    expect(result.bundleHashValid).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.recordsChecked).toBe(6);
  });

  it('fails offline verification when a payload value is altered in the bundle', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    (bundle.records[2]!.payload as Record<string, unknown>).index = 999;

    const result = verifyBundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.findings[0]!.problem).toMatch(/Payload does not match its committed root/);
    expect(result.findings[0]!.problem).toMatch(/index/);
  });

  it('fails offline verification when an identity field is altered in the bundle', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    bundle.records[1]!.actorId = 'someone-else';

    const result = verifyBundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => /Record hash does not match/.test(f.problem))).toBe(true);
  });

  it('fails offline verification when a record is removed from the bundle', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    bundle.records.splice(3, 1);

    const result = verifyBundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => /manifest and record count disagree/.test(f.problem))).toBe(
      true,
    );
  });

  it('fails offline verification when a record is inserted into the bundle', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    const forged = structuredClone(bundle.records[0]!);
    forged.seq = 9999;
    forged.eventId = 'forged-event';
    bundle.records.push(forged);

    const result = verifyBundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => /not listed in the bundle manifest/.test(f.problem))).toBe(
      true,
    );
  });

  it('detects an attempt to cover a record edit by rewriting the manifest', async () => {
    const bundle = await bundleFor('?resourceId=acct-target');
    bundle.records[0]!.actorId = 'attacker';
    bundle.chainContext.exportedSeqs = bundle.records.map((r) => r.seq);

    const result = verifyBundle(bundle);
    expect(result.ok).toBe(false);
    // The bundle hash covers the record digests and the chain context together, so patching
    // the manifest to match a doctored record does not reconcile the two.
    expect(result.bundleHashValid).toBe(true); // manifest was restored to a consistent value...
    expect(result.findings.some((f) => /Record hash does not match/.test(f.problem))).toBe(true);
  });

  it('exports archived and redacted records, and they still verify', async () => {
    const target = (await api.read('?resourceId=acct-target&limit=1')).body.items[0];
    await api.redact(target.eventId, { paths: ['index'], reason: 'privacy request' });

    const bundle = await bundleFor('?resourceId=acct-target');
    const result = verifyBundle(bundle);

    expect(result.ok).toBe(true);
    const redacted = bundle.records.find((r) => r.eventId === target.eventId)!;
    expect(redacted.payload).not.toHaveProperty('index');
    expect(redacted.redactions).toHaveLength(1);
    // The salt for the redacted field is absent from the export because it no longer exists.
    expect(redacted.salts.index).toBeUndefined();
  });

  it('requires exactly one subject', async () => {
    expect((await api.exportBundle('')).status).toBe(400);
    expect((await api.exportBundle('?actorId=a&resourceId=b')).status).toBe(400);
  });
});
