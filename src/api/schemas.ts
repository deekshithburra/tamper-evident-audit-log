/**
 * Request validation at the boundary.
 *
 * An audit log is a permanent, unbounded write surface: whatever gets in stays forever and is
 * covered by a hash that can never be recomputed. So validation here is deliberately strict -
 * bounded lengths, no unknown top-level keys, and a payload that must be a JSON object rather
 * than an arbitrary value.
 */

import { z } from 'zod';
import { assertCanonicalizable } from '../domain/canonical.js';

const identifier = z
  .string()
  .trim()
  .min(1, 'must not be empty')
  .max(256, 'must be at most 256 characters');

const eventTypeSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(
    /^[A-Za-z][A-Za-z0-9_.-]*$/,
    'must start with a letter and contain only letters, digits, underscore, dot or hyphen',
  );

export const writeEventSchema = z
  .object({
    eventType: eventTypeSchema,
    actorId: identifier,
    resourceType: identifier,
    resourceId: identifier,
    payload: z
      .record(z.unknown())
      .refine((value) => !Array.isArray(value), { message: 'payload must be a JSON object' })
      .superRefine((value, ctx) => {
        // Reject values that cannot be canonically serialized *before* they reach the hasher,
        // so the caller gets a 400 naming the field rather than an opaque 500.
        try {
          assertCanonicalizable(value, 'payload');
        } catch (error) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: error instanceof Error ? error.message : 'payload is not serializable',
          });
        }
      }),
    timestamp: z.string().datetime({ offset: true }).optional(),
  })
  .strict();

export const queryEventsSchema = z
  .object({
    actorId: identifier.optional(),
    resourceType: identifier.optional(),
    resourceId: identifier.optional(),
    eventType: eventTypeSchema.optional(),
    from: z.string().datetime({ offset: true }).optional(),
    to: z.string().datetime({ offset: true }).optional(),
    limit: z.coerce.number().int().min(1).max(1000).optional(),
    cursor: z.string().regex(/^\d+$/, 'cursor must be an integer').optional(),
    includeArchived: z
      .enum(['true', 'false'])
      .transform((value) => value === 'true')
      .optional(),
  })
  .strict()
  .refine(
    (value) => value.from === undefined || value.to === undefined || value.from < value.to,
    { message: 'from must be earlier than to', path: ['from'] },
  );

export const verifySchema = z
  .object({
    fromSeq: z.coerce.number().int().min(1).optional(),
  })
  .strict();

export const redactionSchema = z
  .object({
    paths: z
      .array(z.string().trim().min(1).max(512))
      .min(1, 'specify at least one payload path')
      .max(64, 'at most 64 paths per request'),
    reason: z
      .string()
      .trim()
      .min(3, 'a reason is required and is recorded permanently in the chain')
      .max(1024),
  })
  .strict();

export const retentionSchema = z
  .object({
    windowDays: z.coerce.number().int().min(0).max(36_500).optional(),
    limit: z.coerce.number().int().min(1).max(10_000).optional(),
  })
  .strict();

export const exportSchema = z
  .object({
    actorId: identifier.optional(),
    resourceType: identifier.optional(),
    resourceId: identifier.optional(),
  })
  .strict()
  .refine((value) => value.actorId !== undefined || value.resourceId !== undefined, {
    message: 'specify either actorId or resourceId',
  })
  .refine((value) => !(value.actorId !== undefined && value.resourceId !== undefined), {
    message: 'specify actorId or resourceId, not both: an export has one subject',
  });

export const accessReportSchema = z
  .object({
    from: z.string().datetime({ offset: true }),
    to: z.string().datetime({ offset: true }),
    clientId: identifier.optional(),
    actorId: identifier.optional(),
    limit: z.coerce.number().int().min(1).max(1000).optional(),
    cursor: z.string().regex(/^\d+$/).optional(),
  })
  .strict();
