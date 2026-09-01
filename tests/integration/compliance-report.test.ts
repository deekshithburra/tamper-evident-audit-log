import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEYS, buildTestApp, client, sampleEvent } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Scenario C, against the clarified requirement in docs/SCENARIO_C.md.
 *
 * The requirement as stated ("regulators need to be able to audit access to client account
 * data") cannot be tested, because it does not say what "access", "client account data" or
 * "audit" mean. These tests assert the clarified version, and each one names the assumption
 * it depends on so a reviewer can challenge the assumption rather than the code.
 */
describe('client data access report (Scenario C)', () => {
  let application: Application;
  let api: ReturnType<typeof client>;
  const from = '2000-01-01T00:00:00.000Z';
  const to = '2099-01-01T00:00:00.000Z';
  const window = `?from=${from}&to=${to}`;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);

    // Access events to client data: what the report must find.
    await api.write(
      sampleEvent({
        eventType: 'RECORD_VIEWED',
        actorId: 'advisor-7',
        resourceType: 'client_account',
        resourceId: 'client-100',
        payload: { purpose: 'Servicing call SR-4471', fields: ['balance'] },
      }),
    );
    await api.write(
      sampleEvent({
        eventType: 'RECORD_EXPORTED',
        actorId: 'advisor-7',
        resourceType: 'client_statement',
        resourceId: 'client-100',
        payload: { purpose: 'Client requested statement copy' },
      }),
    );
    await api.write(
      sampleEvent({
        eventType: 'RECORD_VIEWED',
        actorId: 'analyst-2',
        resourceType: 'client_position',
        resourceId: 'client-200',
        payload: { note: 'no purpose given' },
      }),
    );

    // Noise the report must exclude: a write to client data, and a read of non-client data.
    await api.write(
      sampleEvent({
        eventType: 'RECORD_UPDATED',
        actorId: 'advisor-7',
        resourceType: 'client_account',
        resourceId: 'client-100',
        payload: { field: 'address' },
      }),
    );
    await api.write(
      sampleEvent({
        eventType: 'RECORD_VIEWED',
        actorId: 'advisor-7',
        resourceType: 'internal_wiki',
        resourceId: 'page-9',
        payload: { purpose: 'reference' },
      }),
    );
  });
  afterEach(() => application.close());

  it('returns only access events against client data', async () => {
    const response = await api.report(window);
    expect(response.status).toBe(200);

    const entries = response.body.entries as Array<{ eventType: string; resourceType: string }>;
    expect(entries).toHaveLength(3);
    expect(entries.every((e) => e.resourceType.startsWith('client_'))).toBe(true);
    // A *write* to client data is not an access to it: the report answers "who looked",
    // which is the regulator's actual question. (Assumption C-2 in docs/SCENARIO_C.md.)
    expect(entries.some((e) => e.eventType === 'RECORD_UPDATED')).toBe(false);
    expect(entries.some((e) => e.resourceType === 'internal_wiki')).toBe(false);
  });

  it('publishes the scope it applied, so the reader can challenge it', async () => {
    // The classification of "client account data" is an assumption, not a fact. A report that
    // hides its own scope cannot be audited, so the scope travels with the answer.
    const response = await api.report(window);
    expect(response.body.scope.clientDataResourceTypes).toContain('client_account');
    expect(response.body.scope.accessEventTypes).toContain('RECORD_VIEWED');
    expect(response.body.criteria).toMatchObject({ from, to });
  });

  it('summarises by actor, client and event type', async () => {
    const response = await api.report(window);
    expect(response.body.summary).toMatchObject({
      totalEvents: 3,
      distinctActors: 2,
      distinctClients: 2,
      byEventType: { RECORD_VIEWED: 2, RECORD_EXPORTED: 1 },
    });
  });

  it('surfaces accesses with no stated purpose as a finding rather than hiding them', async () => {
    const response = await api.report(window);
    expect(response.body.summary.eventsWithoutStatedPurpose).toBe(1);

    const withoutPurpose = (response.body.entries as Array<{ statedPurpose: string | null; actorId: string }>)
      .filter((e) => e.statedPurpose === null);
    expect(withoutPurpose).toHaveLength(1);
    expect(withoutPurpose[0]!.actorId).toBe('analyst-2');
  });

  it('carries integrity evidence, so the report is evidence and not just a spreadsheet', async () => {
    const response = await api.report(window);
    expect(response.body.integrity.chainVerified).toBe(true);
    expect(response.body.integrity.verification.intact).toBe(true);
    expect(response.body.integrity.chainHead.recordHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reports a tampered chain instead of quietly serving results from it', async () => {
    const db = application.repo.unsafeRawHandle();
    db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
    db.exec("UPDATE audit_events SET actor_id = 'covered-up' WHERE seq = 1");

    const response = await api.report(window);
    expect(response.status).toBe(200);
    expect(response.body.integrity.chainVerified).toBe(false);
    expect(response.body.integrity.verification.firstViolation.seq).toBe(1);
    // Results are still returned: a regulator investigating a suspected cover-up needs the
    // data AND the warning, not a 500 that tells them nothing.
    expect(response.body.entries.length).toBeGreaterThan(0);
  });

  it('narrows by client and by actor', async () => {
    const byClient = await api.report(`${window}&clientId=client-100`);
    expect(byClient.body.entries).toHaveLength(2);

    const byActor = await api.report(`${window}&actorId=analyst-2`);
    expect(byActor.body.entries).toHaveLength(1);
    expect(byActor.body.entries[0].actorId).toBe('analyst-2');
  });

  it('restricts the window as asked', async () => {
    const past = await api.report('?from=2000-01-01T00:00:00.000Z&to=2001-01-01T00:00:00.000Z');
    expect(past.body.entries).toHaveLength(0);
    expect(past.body.summary.totalEvents).toBe(0);
  });

  it('AUDITS ITSELF: generating a report appends an event to the same chain', async () => {
    await api.report(window);

    const meta = await api.read('?eventType=COMPLIANCE_REPORT_GENERATED&limit=10');
    expect(meta.body.items).toHaveLength(1);
    expect(meta.body.items[0].actorId).toMatch(/^key:auditor:/);
    expect(meta.body.items[0].payload).toMatchObject({ matchedEvents: 3, returnedEvents: 3 });

    // The chain must still verify after the report wrote to it.
    const verify = await api.verify();
    expect(verify.body.intact).toBe(true);
  });

  it('includes archived accesses, so a historical window is not understated', async () => {
    await api.retention({ windowDays: 0 });
    const response = await api.report(window);

    expect(response.body.summary.totalEvents).toBe(3);
    const archived = (response.body.entries as Array<{ lifecycleState: string }>).filter(
      (e) => e.lifecycleState === 'archived',
    );
    expect(archived.length).toBe(3);
  });

  it('requires from and to, and rejects an inverted window', async () => {
    expect((await api.report('')).status).toBe(400);
    expect((await api.report(`?from=${to}&to=${from}`)).status).toBe(400);
  });

  it('is not readable by a plain reader or writer', async () => {
    expect((await api.report(window, KEYS.reader)).status).toBe(403);
    expect((await api.report(window, KEYS.writer)).status).toBe(403);
    expect((await api.report(window, KEYS.admin)).status).toBe(200);
  });
});
