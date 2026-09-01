import { describe, expect, it } from 'vitest';
import { canonicalize } from '../../src/domain/canonical.js';
import { AppError } from '../../src/domain/errors.js';

describe('canonical serialization', () => {
  it('is independent of object key insertion order', () => {
    const a = { zebra: 1, alpha: { yankee: true, bravo: null }, mike: 'x' };
    const b = { mike: 'x', alpha: { bravo: null, yankee: true }, zebra: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"alpha":{"bravo":null,"yankee":true},"mike":"x","zebra":1}');
  });

  it('preserves array order, which is semantically significant', () => {
    expect(canonicalize([1, 2, 3])).not.toBe(canonicalize([3, 2, 1]));
  });

  it('is stable across 500 randomly shuffled key orderings', () => {
    const source = Object.fromEntries(
      Array.from({ length: 24 }, (_, i) => [`key_${i}`, { n: i, s: `v${i}`, b: i % 2 === 0 }]),
    );
    const expected = canonicalize(source);
    for (let round = 0; round < 500; round += 1) {
      const shuffled = Object.fromEntries(
        Object.entries(source).sort(() => Math.random() - 0.5),
      );
      expect(canonicalize(shuffled)).toBe(expected);
    }
  });

  it('normalizes negative zero, which JSON cannot distinguish from zero', () => {
    expect(canonicalize({ v: -0 })).toBe(canonicalize({ v: 0 }));
  });

  it('rejects values with no deterministic representation', () => {
    expect(() => canonicalize({ v: NaN })).toThrow(AppError);
    expect(() => canonicalize({ v: Infinity })).toThrow(AppError);
    expect(() => canonicalize({ v: undefined })).toThrow(AppError);
    expect(() => canonicalize({ v: () => 1 })).toThrow(AppError);
    expect(() => canonicalize({ v: 10n })).toThrow(AppError);
  });

  it('names the offending path so a rejection is actionable', () => {
    expect(() => canonicalize({ outer: { inner: [1, NaN] } })).toThrow(/outer\.inner\[1\]/);
  });

  it('escapes unicode and control characters consistently', () => {
    expect(canonicalize({ k: 'line\nbreak' })).toBe('{"k":"line\\nbreak"}');
    expect(canonicalize({ k: 'naïve' })).toBe(canonicalize({ k: 'naïve' }));
  });
});
