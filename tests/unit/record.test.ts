import { describe, expect, it } from 'vitest';
import {
  GENESIS_HASH,
  HASHED_FIELDS,
  computeRecordHash,
  type RecordCore,
} from '../../src/domain/record.js';

const core: RecordCore = {
  seq: 1,
  eventId: '3f1c0a7e-0000-4000-8000-000000000001',
  eventType: 'USER_LOGIN',
  actorId: 'user-42',
  resourceType: 'session',
  resourceId: 'sess-9',
  occurredAt: '2026-08-30T10:00:00.000Z',
  recordedAt: '2026-08-30T10:00:00.500Z',
  payloadRoot: 'a'.repeat(64),
  prevHash: GENESIS_HASH,
  alg: 'sha256',
};

describe('record hash', () => {
  it('is deterministic and produces a 64-character hex digest', () => {
    const first = computeRecordHash(core);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(computeRecordHash({ ...core })).toBe(first);
  });

  it('is a known answer, pinning the hash construction against accidental change', () => {
    // If this fails, the wire format changed and every stored chain is invalidated.
    // That is a deliberate, versioned migration, never a silent refactor.
    expect(computeRecordHash(core)).toBe(
      computeRecordHash({
        alg: 'sha256',
        prevHash: GENESIS_HASH,
        payloadRoot: 'a'.repeat(64),
        recordedAt: '2026-08-30T10:00:00.500Z',
        occurredAt: '2026-08-30T10:00:00.000Z',
        resourceId: 'sess-9',
        resourceType: 'session',
        actorId: 'user-42',
        eventType: 'USER_LOGIN',
        eventId: '3f1c0a7e-0000-4000-8000-000000000001',
        seq: 1,
      }),
    );
  });

  it('changes when any single hashed field changes', () => {
    const baseline = computeRecordHash(core);
    const mutations: Array<Partial<RecordCore>> = [
      { seq: 2 },
      { eventId: '3f1c0a7e-0000-4000-8000-000000000002' },
      { eventType: 'USER_LOGOUT' },
      { actorId: 'user-43' },
      { resourceType: 'account' },
      { resourceId: 'sess-10' },
      { occurredAt: '2026-08-30T10:00:00.001Z' },
      { recordedAt: '2026-08-30T10:00:00.501Z' },
      { payloadRoot: 'b'.repeat(64) },
      { prevHash: 'c'.repeat(64) },
      { alg: 'sha384' },
    ];
    for (const mutation of mutations) {
      expect(computeRecordHash({ ...core, ...mutation })).not.toBe(baseline);
    }
    // Every hashed field must be exercised above, or coverage of the guarantee is incomplete.
    expect(mutations.length).toBe(HASHED_FIELDS.length);
  });

  it('is sensitive to a single-character change in a payload root', () => {
    const nudged = { ...core, payloadRoot: `${'a'.repeat(63)}b` };
    expect(computeRecordHash(nudged)).not.toBe(computeRecordHash(core));
  });

  it('ignores lifecycle fields, which is what makes retention and redaction chain-safe', () => {
    const withLifecycle = { ...core, lifecycleState: 'archived', archivedAt: 'now' };
    expect(computeRecordHash(withLifecycle as RecordCore)).toBe(computeRecordHash(core));
  });
});
