/**
 * Domain error taxonomy.
 *
 * These are thrown by pure domain code and translated to HTTP status codes at exactly one
 * place (`src/api/error-handler.ts`), so business logic never imports Express.
 */

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'METHOD_NOT_ALLOWED'
  | 'PAYLOAD_TOO_LARGE'
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_REVOKED'
  | 'CREDENTIAL_NOT_YET_VALID'
  | 'RATE_LIMITED'
  | 'INTERNAL';

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: ErrorCode, status: number, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.details = details;
  }

  static validation(message: string, details?: unknown): AppError {
    return new AppError('VALIDATION_ERROR', 400, message, details);
  }
  static notFound(message: string): AppError {
    return new AppError('NOT_FOUND', 404, message);
  }
  static conflict(message: string): AppError {
    return new AppError('CONFLICT', 409, message);
  }
  static unauthenticated(message = 'Missing or invalid credentials'): AppError {
    return new AppError('UNAUTHENTICATED', 401, message);
  }
  static forbidden(message = 'Insufficient privileges for this operation'): AppError {
    return new AppError('FORBIDDEN', 403, message);
  }
  static tooLarge(message: string): AppError {
    return new AppError('PAYLOAD_TOO_LARGE', 413, message);
  }
  /**
   * 401 rather than 403 for a lapsed credential: the caller is not authenticated, and the
   * distinct code lets a client tell "rotate your key" apart from "you were never allowed".
   */
  static credentialLapsed(code: ErrorCode, message: string): AppError {
    return new AppError(code, 401, message);
  }
  static rateLimited(message: string): AppError {
    return new AppError('RATE_LIMITED', 429, message);
  }
}
