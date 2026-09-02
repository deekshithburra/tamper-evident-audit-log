/**
 * Per-credential rate limiting.
 *
 * Three decisions here are worth defending:
 *
 * **Keyed by credential, not by IP.** Every caller of this service is a server, usually behind
 * a shared egress address, so an IP bucket would either throttle every application together or
 * be trivially evaded. The credential is the thing we actually want to hold accountable, and it
 * is also what appears in the audit trail when the limit is hit.
 *
 * **Separate budgets by cost class.** A write is cheap and bounded. Chain verification, export
 * and the compliance report are O(n) over the whole log - one caller looping `/audit/verify`
 * degrades the service for everyone, and no sensible write budget would stop them. So expensive
 * operations get their own, much smaller allowance.
 *
 * **Fixed window, in memory.** Chosen for a prototype because it is exact, allocation-free and
 * explainable; the cost is a burst of up to 2x the limit across a window boundary. Its real
 * limitation is that it is per-instance: behind two replicas the effective limit doubles.
 * Production wants a shared counter (Redis `INCR` with TTL) or an API gateway. That is a
 * deployment change, not a code change - `RateLimiter` is an interface with one method.
 */

import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../domain/errors.js';
import type { RateLimitClass, RateLimitConfig } from '../config.js';

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Epoch milliseconds at which the current window resets. */
  resetAt: number;
}

export interface RateLimiter {
  consume(key: string, bucket: RateLimitClass): RateLimitDecision;
}

interface WindowState {
  count: number;
  resetAt: number;
}

export class FixedWindowRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, WindowState>();

  constructor(
    private readonly config: RateLimitConfig,
    /** Injected so tests can advance time deterministically instead of sleeping. */
    private readonly now: () => number = () => Date.now(),
  ) {}

  consume(key: string, bucket: RateLimitClass): RateLimitDecision {
    const limit = this.config.limits[bucket];
    const at = this.now();
    const composite = `${bucket}:${key}`;

    let state = this.windows.get(composite);
    if (state === undefined || at >= state.resetAt) {
      state = { count: 0, resetAt: at + this.config.windowMs };
      this.windows.set(composite, state);
      this.evictExpired(at);
    }

    if (state.count >= limit) {
      return { allowed: false, limit, remaining: 0, resetAt: state.resetAt };
    }

    state.count += 1;
    return { allowed: true, limit, remaining: limit - state.count, resetAt: state.resetAt };
  }

  /**
   * Bound the map so a stream of distinct keys cannot grow it without limit - a rate limiter
   * that can be turned into a memory-exhaustion vector is worse than none.
   */
  private evictExpired(at: number): void {
    if (this.windows.size < 1024) return;
    for (const [key, state] of this.windows) {
      if (at >= state.resetAt) this.windows.delete(key);
    }
  }
}

/** No-op limiter, used when rate limiting is disabled and as a test double. */
export class UnlimitedRateLimiter implements RateLimiter {
  consume(_key: string, _bucket: RateLimitClass): RateLimitDecision {
    return { allowed: true, limit: Number.POSITIVE_INFINITY, remaining: Number.POSITIVE_INFINITY, resetAt: 0 };
  }
}

/**
 * Middleware factory. Applied per route with its cost class, so the budget a call consumes is
 * declared at the point the route is defined and is visible when reading the router.
 */
export function rateLimit(limiter: RateLimiter, bucket: RateLimitClass) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Unauthenticated requests never reach here (authenticate runs first), but fall back to the
    // socket address rather than a shared bucket if the order ever changes.
    const key = req.principal?.id ?? req.ip ?? 'anonymous';
    const decision = limiter.consume(key, bucket);

    if (Number.isFinite(decision.limit)) {
      res.set('X-RateLimit-Limit', String(decision.limit));
      res.set('X-RateLimit-Remaining', String(Math.max(0, decision.remaining)));
      res.set('X-RateLimit-Reset', new Date(decision.resetAt).toISOString());
    }

    if (!decision.allowed) {
      const retryAfterSeconds = Math.max(1, Math.ceil((decision.resetAt - Date.now()) / 1000));
      res.set('Retry-After', String(retryAfterSeconds));
      next(
        AppError.rateLimited(
          `Rate limit exceeded for this credential on ${bucket} operations ` +
            `(${decision.limit} per window). Retry in ${retryAfterSeconds}s.`,
        ),
      );
      return;
    }

    next();
  };
}
