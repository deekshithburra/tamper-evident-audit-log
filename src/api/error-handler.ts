/**
 * The single translation point between domain errors and HTTP.
 *
 * Two rules worth stating: an unexpected error never leaks its message or stack to the client
 * (in an audit service, internals are exactly what an attacker is probing for), and every
 * response carries a stable machine-readable `code` so callers branch on that rather than on
 * prose we may reword.
 */

import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../domain/errors.js';
import type { Logger } from 'pino';

export interface ErrorBody {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: { code: 'NOT_FOUND', message: `No route for ${req.method} ${req.path}` },
  } satisfies ErrorBody);
}

export function errorHandler(logger: Logger) {
  return (error: unknown, _req: Request, res: Response, next: NextFunction): void => {
    if (res.headersSent) {
      next(error);
      return;
    }

    if (error instanceof AppError) {
      res.status(error.status).json({
        error: {
          code: error.code,
          message: error.message,
          ...(error.details === undefined ? {} : { details: error.details }),
        },
      } satisfies ErrorBody);
      return;
    }

    if (error instanceof ZodError) {
      res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request failed validation',
          details: error.issues.map((issue) => ({
            path: issue.path.join('.'),
            message: issue.message,
          })),
        },
      } satisfies ErrorBody);
      return;
    }

    // Body-parser surfaces malformed JSON and oversized bodies as plain Errors with a status.
    const status = (error as { status?: number; type?: string }).status;
    if (status === 400 && (error as { type?: string }).type === 'entity.parse.failed') {
      res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Request body is not valid JSON' },
      } satisfies ErrorBody);
      return;
    }
    if (status === 413) {
      res.status(413).json({
        error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the configured limit' },
      } satisfies ErrorBody);
      return;
    }

    logger.error({ err: error }, 'Unhandled error while serving request');
    res.status(500).json({
      error: { code: 'INTERNAL', message: 'Internal server error' },
    } satisfies ErrorBody);
  };
}
