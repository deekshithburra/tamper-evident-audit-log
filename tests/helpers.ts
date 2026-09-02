import { createServer, type Server } from 'node:http';
import request from 'supertest';
import { createApplication, type Application, type ApplicationOptions } from '../src/app.js';

export const KEYS = {
  writer: 'test-writer-key',
  reader: 'test-reader-key',
  auditor: 'test-auditor-key',
  admin: 'test-admin-key',
} as const;

const TEST_ENV = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  // Rate limiting is exercised deliberately in its own suite; leaving it on everywhere would
  // make unrelated suites fail intermittently once they grew past the window budget.
  RATE_LIMIT_ENABLED: 'false',
  // Every suite gets its own in-memory database: no fixtures, no cleanup, no cross-test bleed.
  DATABASE_PATH: ':memory:',
  API_KEYS: `${KEYS.writer}:writer,${KEYS.reader}:reader,${KEYS.auditor}:auditor,${KEYS.admin}:admin`,
} satisfies NodeJS.ProcessEnv;

const servers = new WeakMap<Application, Server>();

/**
 * Bind each test application to an explicit loopback address, and wait for the bind.
 *
 * Both halves matter, and both were found the hard way:
 *
 *  - `listen(0)` binds dual-stack (`::`). The port is then free in the IPv6 space but may be
 *    held on IPv4 by an unrelated process on the machine, so a request to `127.0.0.1:<port>`
 *    can reach *that* process instead. It surfaced here as sporadic 404s, ECONNRESETs, and -
 *    unmistakably - one 401 whose body was another service's error envelope. Binding
 *    `127.0.0.1` explicitly makes the port ours on the interface the client actually dials.
 *  - Awaiting the bind matters because supertest, handed a server with no address yet, quietly
 *    calls `listen(0)` on it again and sends the request somewhere else entirely.
 *
 * Letting supertest manage an ephemeral listener per request has the same dual-stack exposure,
 * multiplied by request count.
 */
export async function buildTestApp(
  overrides: NodeJS.ProcessEnv = {},
  options: ApplicationOptions = {},
): Promise<Application> {
  const application = createApplication({}, { ...TEST_ENV, ...overrides }, options);
  const server = createServer(application.app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  servers.set(application, server);

  const closeApplication = application.close;
  application.close = () => {
    server.close();
    closeApplication();
  };
  return application;
}

export function client(application: Application) {
  const server = servers.get(application);
  if (server === undefined) throw new Error('Test application was not built by buildTestApp');
  const agent = request.agent(server);
  return {
    write: (body: unknown, key: string = KEYS.writer) =>
      agent.post('/audit/events').set('X-API-Key', key).send(body as object),
    read: (query = '', key: string = KEYS.reader) =>
      agent.get(`/audit/events${query}`).set('X-API-Key', key),
    getOne: (eventId: string, key: string = KEYS.reader) =>
      agent.get(`/audit/events/${eventId}`).set('X-API-Key', key),
    verify: (query = '', key: string = KEYS.auditor) =>
      agent.get(`/audit/verify${query}`).set('X-API-Key', key),
    redact: (eventId: string, body: unknown, key: string = KEYS.admin) =>
      agent
        .post(`/audit/events/${eventId}/redactions`)
        .set('X-API-Key', key)
        .send(body as object),
    retention: (body: unknown = {}, key: string = KEYS.admin) =>
      agent.post('/audit/retention/apply').set('X-API-Key', key).send(body as object),
    exportBundle: (query: string, key: string = KEYS.auditor) =>
      agent.get(`/audit/export${query}`).set('X-API-Key', key),
    report: (query: string, key: string = KEYS.auditor) =>
      agent.get(`/audit/reports/client-data-access${query}`).set('X-API-Key', key),
    raw: agent,
  };
}

export function sampleEvent(overrides: Record<string, unknown> = {}) {
  return {
    eventType: 'RECORD_UPDATED',
    actorId: 'user-1',
    resourceType: 'client_account',
    resourceId: 'acct-1000',
    payload: { field: 'address', previous: 'old', current: 'new' },
    ...overrides,
  };
}

/**
 * Write `count` events through the real HTTP path, so tests exercise validation, hashing and
 * persistence exactly as production would.
 */
export async function seed(
  application: Application,
  count: number,
  shape: (index: number) => Record<string, unknown> = () => ({}),
): Promise<Array<Record<string, unknown>>> {
  const api = client(application);
  const created: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i += 1) {
    const response = await api.write(sampleEvent(shape(i)));
    if (response.status !== 201) {
      throw new Error(`Seed write ${i} failed: ${response.status} ${JSON.stringify(response.body)}`);
    }
    created.push(response.body as Record<string, unknown>);
  }
  return created;
}

/**
 * Simulate an attacker with direct datastore access.
 *
 * The schema triggers deliberately block edits to hashed columns, so this drops them first -
 * which is precisely the threat model in ADR-0002: the triggers stop accidents and casual
 * tampering, and the hash chain is what catches an attacker who defeats them.
 */
export function tamperDirectly(application: Application, sql: string, params: unknown[] = []): void {
  const db = application.repo.unsafeRawHandle();
  db.exec('DROP TRIGGER IF EXISTS audit_events_immutable_update');
  db.exec('DROP TRIGGER IF EXISTS audit_events_no_delete');
  db.exec('DROP TRIGGER IF EXISTS audit_events_lifecycle_forward_only');
  db.prepare(sql).run(...(params as never[]));
}

/** An authenticated request helper for an arbitrary key, for suites that mint their own. */
export function withKey(application: Application, key: string) {
  const api = client(application);
  return {
    write: (body: unknown) => api.write(body, key),
    read: (query = '') => api.read(query, key),
    getOne: (eventId: string) => api.getOne(eventId, key),
    verify: (query = '') => api.verify(query, key),
    exportBundle: (query: string) => api.exportBundle(query, key),
    report: (query: string) => api.report(query, key),
    redact: (eventId: string, body: unknown) => api.redact(eventId, body, key),
    whoami: () => api.raw.get('/auth/whoami').set('X-API-Key', key),
    credentials: () => api.raw.get('/auth/credentials').set('X-API-Key', key),
  };
}
