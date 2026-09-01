import { describe, expect, it } from 'vitest';
import {
  commitPayload,
  escapeSegment,
  flatten,
  leafDigest,
  merkleRoot,
  recomputeRoot,
} from '../../src/domain/commitments.js';
import { AppError } from '../../src/domain/errors.js';

const payload = {
  account: { number: '1234567890', holder: 'A. Client' },
  amount: 250.5,
  tags: ['wire', 'international'],
};

describe('payload flattening', () => {
  it('produces one leaf per scalar, with index-qualified array paths', () => {
    const paths = flatten(payload).map(([p]) => p);
    expect(paths.sort()).toEqual([
      'account.holder',
      'account.number',
      'amount',
      'tags.0',
      'tags.1',
    ]);
  });

  it('commits to empty containers so they cannot be added or removed silently', () => {
    expect(flatten({ a: {} })).toEqual([['a', {}]]);
    expect(flatten({ a: [] })).toEqual([['a', []]]);
    // Same path, same salt, different empty container: the commitments must still differ.
    expect(leafDigest('a', 'fixed-salt', {})).not.toBe(leafDigest('a', 'fixed-salt', []));
  });

  it('escapes dots in keys so nesting cannot be forged by key naming', () => {
    expect(escapeSegment('a.b')).toBe('a~1b');
    const nested = flatten({ a: { b: 1 } }).map(([p]) => p);
    const dotted = flatten({ 'a.b': 1 }).map(([p]) => p);
    expect(nested).not.toEqual(dotted);
  });

  it('rejects payloads that exceed the structural guardrails', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 20; i += 1) deep = { nest: deep };
    expect(() => commitPayload(deep)).toThrow(AppError);

    const wide = Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`k${i}`, i]));
    expect(() => commitPayload(wide)).toThrow(/leaf fields/);
  });
});

describe('salted commitments', () => {
  it('produces different leaf digests for the same value under different salts', () => {
    const a = leafDigest('account.number', 'aaaa', '1234567890');
    const b = leafDigest('account.number', 'bbbb', '1234567890');
    expect(a).not.toBe(b);
  });

  it('binds the path, so an equal value at another path commits differently', () => {
    expect(leafDigest('a', 'salt', 'v')).not.toBe(leafDigest('b', 'salt', 'v'));
  });

  it('is deterministic given the same path, salt and value', () => {
    expect(leafDigest('a', 'salt', 'v')).toBe(leafDigest('a', 'salt', 'v'));
  });

  it('generates a fresh salt per field, so identical values do not reveal each other', () => {
    const commitment = commitPayload({ first: 'same-value', second: 'same-value' });
    expect(commitment.salts.first).not.toBe(commitment.salts.second);
    const digests = commitment.leaves.map((leaf) => leaf.digest);
    expect(new Set(digests).size).toBe(2);
  });
});

describe('merkle root', () => {
  it('is order-independent over leaves but bound to the leaf set', () => {
    const commitment = commitPayload(payload);
    const shuffled = [...commitment.leaves].reverse();
    expect(merkleRoot(shuffled)).toBe(commitment.root);
  });

  it('changes if any leaf changes', () => {
    const commitment = commitPayload(payload);
    const mutated = commitment.leaves.map((leaf, i) =>
      // Flip the first nibble to a guaranteed-different value. Replacing it with a constant
      // is a no-op whenever the digest already starts with that character.
      i === 0
        ? { ...leaf, digest: (leaf.digest[0] === '0' ? '1' : '0') + leaf.digest.slice(1) }
        : leaf,
    );
    expect(merkleRoot(mutated)).not.toBe(commitment.root);
  });

  it('binds the leaf count, defeating odd-node promotion ambiguity', () => {
    const three = commitPayload({ a: 1, b: 2, c: 3 });
    const four = { ...three, leaves: [...three.leaves, three.leaves[0]!] };
    expect(merkleRoot(four.leaves)).not.toBe(three.root);
  });
});

describe('root recomputation (the redaction-safety property)', () => {
  it('recomputes the identical root from intact plaintext and salts', () => {
    const commitment = commitPayload(payload);
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts: commitment.salts,
      payload,
    });
    expect(root).toBe(commitment.root);
    expect(mismatchedPaths).toEqual([]);
  });

  it('yields the identical root after a field and its salt are destroyed', () => {
    const commitment = commitPayload(payload);
    const redactedPayload = {
      ...payload,
      account: { holder: payload.account.holder },
    };
    const remainingSalts = { ...commitment.salts };
    delete remainingSalts['account.number'];

    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts: remainingSalts,
      payload: redactedPayload,
    });

    expect(root).toBe(commitment.root);
    expect(mismatchedPaths).toEqual([]);
  });

  it('detects a value altered in place while its salt is retained', () => {
    const commitment = commitPayload(payload);
    const tampered = { ...payload, amount: 999999 };
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts: commitment.salts,
      payload: tampered,
    });
    expect(root).not.toBe(commitment.root);
    expect(mismatchedPaths).toContain('amount');
  });

  it('treats a container emptied by redaction as erasure, not injection', () => {
    // Redacting the last surviving field of an object leaves `{account:{}}`, and flatten
    // commits empty containers as leaves - so the naive check reads the emptied container as
    // an injected field and reports a false tamper on a legitimate erasure.
    const commitment = commitPayload({ account: { number: '123456789' }, keep: 1 });
    const salts = { ...commitment.salts };
    delete salts['account.number'];

    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts,
      payload: { account: {}, keep: 1 },
    });

    expect(mismatchedPaths).toEqual([]);
    expect(root).toBe(commitment.root);
  });

  it('still rejects an empty container injected where nothing was committed', () => {
    const commitment = commitPayload({ keep: 1 });
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts: commitment.salts,
      payload: { keep: 1, injected: {} },
    });

    expect(mismatchedPaths).toContain('injected');
    expect(root).not.toBe(commitment.root);
  });

  it('detects a field appended to the payload after the fact', () => {
    const commitment = commitPayload(payload);
    const { root, mismatchedPaths } = recomputeRoot({
      storedLeaves: commitment.leaves,
      salts: commitment.salts,
      payload: { ...payload, injected: 'new' },
    });
    expect(mismatchedPaths).toContain('injected');
    expect(root).not.toBe(commitment.root);
  });
});
