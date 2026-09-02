import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, client, sampleEvent, withKey } from '../helpers.js';
import type { Application } from '../../src/app.js';

/**
 * Object-level authorization (BOLA).
 *
 * Role checks answer "may this principal call this endpoint". They do not answer "may this
 * principal see *this record*", and that gap is the most commonly exploited API vulnerability
 * there is: a legitimately issued `reader` key walking the entire audit log by iterating event
 * ids, one request at a time, without ever failing an authorization check.
 *
 * The credentials below are scoped to a single client and to a single actor respectively. Every
 * test asks the same question from a different direction: can a scoped credential reach an
 * object outside its scope, by any route the API offers?
 */

const CREDENTIALS = JSON.stringify([
  { id: 'ops-unscoped', secret: 'unscoped-admin-key', role: 'admin' },
  {
    id: 'desk-west',
    secret: 'west-desk-key-01',
    role: 'admin',
    scope: { resourceIds: ['client-100'] },
    description: 'West desk: one client only',
  },
  {
    id: 'advisor-self',
    secret: 'advisor-self-key-1',
    role: 'auditor',
    scope: { actorIds: ['advisor-7'] },
    description: 'Advisor self-service: own activity only',
  },
  {
    id: 'statements-only',
    secret: 'statements-key-001',
    role: 'auditor',
    scope: { resourceTypes: ['client_statement'] },
  },
]);

describe('object-level authorization (BOLA mitigation)', () => {
  let application: Application;
  let unscoped: ReturnType<typeof withKey>;
  let westDesk: ReturnType<typeof withKey>;
  let advisor: ReturnType<typeof withKey>;
  let statements: ReturnType<typeof withKey>;
  let ids: Record<string, string>;

  beforeEach(async () => {
    application = await buildTestApp({ API_CREDENTIALS: CREDENTIALS });
    const api = client(application);
    unscoped = withKey(application, 'unscoped-admin-key');
    westDesk = withKey(application, 'west-desk-key-01');
    advisor = withKey(application, 'advisor-self-key-1');
    statements = withKey(application, 'statements-key-001');

    const written = {
      west: await api.write(
        sampleEvent({
          actorId: 'advisor-7',
          resourceType: 'client_account',
          resourceId: 'client-100',
          eventType: 'RECORD_VIEWED',
          payload: { purpose: 'servicing', balance: 1000 },
        }),
        'unscoped-admin-key',
      ),
      east: await api.write(
        sampleEvent({
          actorId: 'advisor-9',
          resourceType: 'client_account',
          resourceId: 'client-200',
          eventType: 'RECORD_VIEWED',
          payload: { purpose: 'servicing', balance: 9999 },
        }),
        'unscoped-admin-key',
      ),
      statement: await api.write(
        sampleEvent({
          actorId: 'advisor-9',
          resourceType: 'client_statement',
          resourceId: 'client-200',
          eventType: 'RECORD_EXPORTED',
          payload: { purpose: 'copy request' },
        }),
        'unscoped-admin-key',
      ),
    };

    ids = {
      west: written.west.body.eventId,
      east: written.east.body.eventId,
      statement: written.statement.body.eventId,
    };
  });
  afterEach(() => application.close());

  describe('the core failure this prevents', () => {
    it('DOES NOT let a scoped credential read another client’s record by its event id', async () => {
      // The classic BOLA exploit: a valid credential, a valid endpoint, someone else's object.
      const response = await westDesk.getOne(ids.east as string);
      expect(response.status).toBe(404);
    });

    it('returns 404 rather than 403, so the API is not an existence oracle', async () => {
      const outOfScope = await westDesk.getOne(ids.east as string);
      const nonExistent = await westDesk.getOne('11111111-2222-3333-4444-555555555555');

      // Indistinguishable responses. A 403 here would confirm the id exists, which is all an
      // attacker needs to enumerate the log they cannot read. The two bodies differ only where
      // they echo back the id the caller themselves supplied, so normalise that out and require
      // everything else to be identical.
      const normalise = (body: { error: { code: string; message: string } }, id: string) => ({
        ...body,
        error: { ...body.error, message: body.error.message.replace(id, '<id>') },
      });

      expect(outOfScope.status).toBe(nonExistent.status);
      expect(normalise(outOfScope.body, ids.east as string)).toEqual(
        normalise(nonExistent.body, '11111111-2222-3333-4444-555555555555'),
      );
    });

    it('still serves records inside the scope', async () => {
      const response = await westDesk.getOne(ids.west as string);
      expect(response.status).toBe(200);
      expect(response.body.resourceId).toBe('client-100');
    });
  });

  describe('collection queries', () => {
    it('silently narrows an unfiltered query to the scope instead of returning everything', async () => {
      const all = await unscoped.read('?limit=100');
      const scoped = await westDesk.read('?limit=100');

      expect(all.body.items.length).toBeGreaterThan(scoped.body.items.length);
      expect(
        scoped.body.items.every((r: { resourceId: string }) => r.resourceId === 'client-100'),
      ).toBe(true);
    });

    it('scopes by actor as well as by resource', async () => {
      const response = await advisor.read('?limit=100');
      expect(response.body.items.length).toBeGreaterThan(0);
      expect(response.body.items.every((r: { actorId: string }) => r.actorId === 'advisor-7')).toBe(
        true,
      );
    });

    it('scopes by resource type', async () => {
      const response = await statements.read('?limit=100');
      expect(
        response.body.items.every((r: { resourceType: string }) => r.resourceType === 'client_statement'),
      ).toBe(true);
      expect(response.body.items.length).toBe(1);
    });

    it('refuses an explicit filter that names a value outside the scope', async () => {
      // 403 is safe here: the caller supplied the value, so refusing it reveals nothing new.
      const response = await westDesk.read('?resourceId=client-200');
      expect(response.status).toBe(403);
      expect(response.body.error.message).toMatch(/not scoped to resourceId "client-200"/);
    });

    it('permits an explicit filter that names a value inside the scope', async () => {
      const response = await westDesk.read('?resourceId=client-100');
      expect(response.status).toBe(200);
      expect(response.body.items.length).toBeGreaterThan(0);
    });

    it('cannot be widened by paginating past the scope', async () => {
      // Cursor pagination must not become a way to walk out of the allow-list.
      let cursor: string | null = null;
      const seen: string[] = [];
      do {
        const query: string = cursor === null ? '?limit=1' : `?limit=1&cursor=${cursor}`;
        const page = await westDesk.read(query);
        seen.push(...(page.body.items as Array<{ resourceId: string }>).map((r) => r.resourceId));
        cursor = page.body.nextCursor;
      } while (cursor !== null && seen.length < 20);

      expect(seen.every((id) => id === 'client-100')).toBe(true);
    });
  });

  describe('every other route that can reach a record', () => {
    it('refuses an export of an out-of-scope subject', async () => {
      // Export names its subject, so 403 rather than an empty bundle: an empty bundle would
      // read as "this client has no history", which is a different and misleading claim.
      const response = await westDesk.exportBundle('?resourceId=client-200');
      expect(response.status).toBe(403);
    });

    it('allows an export inside the scope', async () => {
      const response = await westDesk.exportBundle('?resourceId=client-100');
      expect(response.status).toBe(200);
      expect(response.body.records.length).toBeGreaterThan(0);
    });

    it('narrows the compliance report to the scope', async () => {
      const window = '?from=2000-01-01T00:00:00.000Z&to=2099-01-01T00:00:00.000Z';
      const full = await unscoped.report(window);
      const scoped = await westDesk.report(window);

      expect(scoped.body.summary.totalEvents).toBeLessThan(full.body.summary.totalEvents);
      expect(
        (scoped.body.entries as Array<{ resourceId: string }>).every((e) => e.resourceId === 'client-100'),
      ).toBe(true);
    });

    it('refuses to redact an out-of-scope record, and does not confirm it exists', async () => {
      const response = await westDesk.redact(ids.east as string, {
        paths: ['balance'],
        reason: 'attempted cross-tenant redaction',
      });
      expect(response.status).toBe(404);
    });

    it('permits redaction inside the scope', async () => {
      const response = await westDesk.redact(ids.west as string, {
        paths: ['balance'],
        reason: 'privacy request',
      });
      expect(response.status).toBe(200);
    });
  });

  describe('unscoped credentials are unaffected', () => {
    it('sees everything', async () => {
      const response = await unscoped.read('?limit=100');
      const resourceIds = new Set(
        (response.body.items as Array<{ resourceId: string }>).map((r) => r.resourceId),
      );
      expect(resourceIds.has('client-100')).toBe(true);
      expect(resourceIds.has('client-200')).toBe(true);
    });
  });

  describe('self-description', () => {
    it('tells a caller its own scope, so a client can verify what it was issued', async () => {
      const scoped = await westDesk.whoami();
      expect(scoped.status).toBe(200);
      expect(scoped.body).toMatchObject({
        id: 'desk-west',
        role: 'admin',
        scope: { resourceIds: ['client-100'], unrestricted: false },
      });
      expect(scoped.body.capabilities).toContain('records:redact');

      const open = await unscoped.whoami();
      expect(open.body.scope.unrestricted).toBe(true);
    });

    it('never reveals a secret through the identity endpoints', async () => {
      const inventory = await unscoped.credentials();
      expect(inventory.status).toBe(200);
      const body = JSON.stringify(inventory.body);
      for (const secret of ['unscoped-admin-key', 'west-desk-key-01', 'advisor-self-key-1']) {
        expect(body).not.toContain(secret);
      }
      expect(inventory.body.credentials.map((c: { id: string }) => c.id)).toContain('desk-west');
    });

    it('does not expose the credential inventory to a non-admin', async () => {
      const response = await advisor.credentials();
      expect(response.status).toBe(403);
    });
  });
});
