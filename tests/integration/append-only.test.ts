import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEYS, buildTestApp, client, seed } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Requirement A2: the API must not expose an update or delete operation.
 *
 * These tests check all three enforcement layers that live in code (ADR-0002). The fourth,
 * the hash chain itself, is covered by tamper.test.ts.
 */
describe('append-only enforcement', () => {
  let application: Application;
  let api: ReturnType<typeof client>;

  beforeEach(async () => {
    application = await buildTestApp();
    api = client(application);
    await seed(application, 3);
  });
  afterEach(() => application.close());

  describe('layer 1: the HTTP surface exposes no mutation', () => {
    it('refuses PUT, PATCH and DELETE with an explanatory 405', async () => {
      const all = await api.read('?limit=10');
      const eventId = all.body.items[0].eventId;

      for (const method of ['put', 'patch', 'delete'] as const) {
        const response = await api.raw[method](`/audit/events/${eventId}`)
          .set('X-API-Key', KEYS.admin)
          .send({ actorId: 'attacker' });

        expect(response.status).toBe(405);
        expect(response.body.error.code).toBe('METHOD_NOT_ALLOWED');
        // The refusal must point the caller at the legitimate alternatives, or they will
        // reach for the database instead.
        expect(response.body.error.message).toMatch(/append a compensating event/);
        expect(response.body.error.message).toMatch(/redactions/);
        expect(response.headers.allow).toBe('GET, POST');
      }
    });

    it('refuses collection-level mutation too', async () => {
      const response = await api.raw.delete('/audit/events').set('X-API-Key', KEYS.admin);
      expect(response.status).toBe(405);
    });
  });

  describe('layer 3: the database refuses mutation of hashed columns', () => {
    const hashedColumnUpdates: Array<[string, string]> = [
      ['actor_id', "UPDATE audit_events SET actor_id = 'attacker' WHERE seq = 2"],
      ['event_type', "UPDATE audit_events SET event_type = 'FORGED' WHERE seq = 2"],
      ['payload_root', "UPDATE audit_events SET payload_root = 'deadbeef' WHERE seq = 2"],
      ['prev_hash', "UPDATE audit_events SET prev_hash = 'deadbeef' WHERE seq = 2"],
      ['record_hash', "UPDATE audit_events SET record_hash = 'deadbeef' WHERE seq = 2"],
      ['recorded_at', "UPDATE audit_events SET recorded_at = '1999-01-01' WHERE seq = 2"],
      ['leaves_json', "UPDATE audit_events SET leaves_json = '[]' WHERE seq = 2"],
    ];

    for (const [column, sql] of hashedColumnUpdates) {
      it(`aborts an UPDATE of ${column}`, () => {
        const db = application.repo.unsafeRawHandle();
        expect(() => db.exec(sql)).toThrow(/append-only/);
      });
    }

    it('aborts a DELETE outright', () => {
      const db = application.repo.unsafeRawHandle();
      expect(() => db.exec('DELETE FROM audit_events WHERE seq = 2')).toThrow(/append-only/);
      expect(() => db.exec('DELETE FROM audit_events')).toThrow(/append-only/);
      expect(application.repo.count()).toBe(3);
    });

    it('permits the policy columns, which is what makes redaction and archival possible', () => {
      const db = application.repo.unsafeRawHandle();
      expect(() =>
        db.exec("UPDATE audit_events SET payload_json = '{}', field_salts_json = '{}' WHERE seq = 2"),
      ).not.toThrow();
    });

    it('refuses to move a record back from archived to active', () => {
      const db = application.repo.unsafeRawHandle();
      db.exec("UPDATE audit_events SET lifecycle_state = 'archived' WHERE seq = 2");
      expect(() =>
        db.exec("UPDATE audit_events SET lifecycle_state = 'active' WHERE seq = 2"),
      ).toThrow(/cannot move back from archived/);
    });

    it('refuses a second record claiming the same predecessor (a forked chain)', () => {
      const db = application.repo.unsafeRawHandle();
      const existing = application.repo.getBySeq(2)!;
      expect(() =>
        db
          .prepare(
            `INSERT INTO audit_events (event_id, event_type, actor_id, resource_type, resource_id,
              occurred_at, recorded_at, payload_root, prev_hash, alg, record_hash, leaves_json,
              payload_json, field_salts_json)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          )
          .run(
            'forked-event',
            'FORGED',
            'attacker',
            'client_account',
            'acct-1',
            existing.occurredAt,
            existing.recordedAt,
            existing.payloadRoot,
            existing.prevHash, // same predecessor as seq 2
            'sha256',
            'f'.repeat(64),
            '[]',
            '{}',
            '{}',
          ),
      ).toThrow(/UNIQUE/);
    });
  });
});
