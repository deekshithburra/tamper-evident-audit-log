/**
 * Canonical JSON serialization (RFC 8785-flavoured).
 *
 * Hashing must be reproducible on any machine, in any runtime, at any future date. Plain
 * `JSON.stringify` is not: object key order follows insertion order, and values with no
 * stable JSON representation (`NaN`, `undefined`, `-0`) serialize lossily or throw. Either
 * would cause an independent verifier to report a false tamper, which is the worst failure
 * mode this system has: it destroys trust in the true positives too.
 *
 * Rules:
 *   - Object keys sorted by UTF-16 code unit, recursively.
 *   - No insignificant whitespace.
 *   - Negative zero normalized to zero (indistinguishable in JSON, distinct in JS).
 *   - `undefined`, functions, symbols, `NaN`, infinities and BigInt are rejected loudly
 *     rather than coerced. An audit log should refuse ambiguous input, not guess at it.
 */

import { AppError } from './errors.js';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function canonicalize(value: unknown, path = '$'): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number': {
      if (!Number.isFinite(value)) {
        throw AppError.validation(
          `Non-finite number at ${path}: values must be finite to be hashed deterministically`,
        );
      }
      // Object.is distinguishes -0 from 0; JSON does not. Normalize so two payloads that are
      // indistinguishable as JSON cannot produce two different digests.
      return JSON.stringify(Object.is(value, -0) ? 0 : value);
    }

    case 'string':
      return JSON.stringify(value);

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((item, i) => canonicalize(item, `${path}[${i}]`)).join(',')}]`;
      }
      const entries = Object.entries(value as Record<string, unknown>);
      for (const [key, item] of entries) {
        if (item === undefined) {
          throw AppError.validation(
            `Undefined value at ${path}.${key}: not representable in JSON`,
          );
        }
      }
      entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      const body = entries
        .map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item, `${path}.${key}`)}`)
        .join(',');
      return `{${body}}`;
    }

    default:
      throw AppError.validation(
        `Unsupported value of type "${typeof value}" at ${path}: cannot be canonically serialized`,
      );
  }
}

/** Structural check used by request validation, so bad input is rejected at the boundary. */
export function assertCanonicalizable(value: unknown, path = '$'): void {
  canonicalize(value, path);
}
