/**
 * Object-level access scope (BOLA mitigation).
 *
 * Role-based checks answer "may this principal call this endpoint". They do not answer "may
 * this principal see *this record*" - and that gap is Broken Object Level Authorization, the
 * most common API vulnerability there is. A `reader` key issued to one business unit could,
 * before this existed, read every audit record in the system by iterating event ids.
 *
 * A scope is a per-credential allow-list over the three identity dimensions of a record. It
 * lives in `domain/` rather than in the auth middleware on purpose: enforcement happens in the
 * service layer, so it cannot be bypassed by a future transport (a queue consumer, a gRPC
 * surface) that forgets to run an Express middleware.
 *
 * An absent dimension means "unrestricted on that dimension". An empty scope object means
 * unrestricted entirely - which is what the operator-level credentials use.
 */

import { AppError } from './errors.js';

export interface AccessScope {
  /** Records whose `actorId` is one of these. */
  actorIds?: string[];
  /** Records whose `resourceType` is one of these. */
  resourceTypes?: string[];
  /** Records whose `resourceId` is one of these. */
  resourceIds?: string[];
}

export const UNSCOPED: AccessScope = {};

export function isUnscoped(scope: AccessScope | undefined): boolean {
  if (scope === undefined) return true;
  return (
    scope.actorIds === undefined &&
    scope.resourceTypes === undefined &&
    scope.resourceIds === undefined
  );
}

/** Does this record fall inside the scope? Used for single-object checks. */
export function permits(
  scope: AccessScope | undefined,
  record: { actorId: string; resourceType: string; resourceId: string },
): boolean {
  if (scope === undefined) return true;
  if (scope.actorIds !== undefined && !scope.actorIds.includes(record.actorId)) return false;
  if (scope.resourceTypes !== undefined && !scope.resourceTypes.includes(record.resourceType)) {
    return false;
  }
  if (scope.resourceIds !== undefined && !scope.resourceIds.includes(record.resourceId)) {
    return false;
  }
  return true;
}

/**
 * Check an explicitly requested value against the scope.
 *
 * A 403 here is safe and useful: the caller named the value themselves, so refusing it reveals
 * nothing they did not already supply. This is deliberately *not* how single-record lookups
 * behave - see `AuditService.getByEventId`, which returns 404 for an out-of-scope record so
 * that the API cannot be used to test whether a given event id exists.
 */
export function assertRequestedValueInScope(
  scope: AccessScope | undefined,
  dimension: keyof AccessScope,
  requested: string | undefined,
): void {
  if (scope === undefined || requested === undefined) return;
  const allowed = scope[dimension];
  if (allowed === undefined) return;
  if (!allowed.includes(requested)) {
    throw AppError.forbidden(
      `This credential is not scoped to ${labelFor(dimension)} "${requested}"`,
    );
  }
}

function labelFor(dimension: keyof AccessScope): string {
  switch (dimension) {
    case 'actorIds':
      return 'actorId';
    case 'resourceTypes':
      return 'resourceType';
    default:
      return 'resourceId';
  }
}

/**
 * Narrow a set of query filters to the scope.
 *
 * Explicitly requested values are validated (403 if outside); dimensions the caller left open
 * get the scope injected as an `IN` filter, so an unfiltered query returns only what the
 * credential may see rather than everything.
 */
export function narrowFilters<
  T extends {
    actorId?: string;
    resourceType?: string;
    resourceId?: string;
    actorIdIn?: string[];
    resourceTypeIn?: string[];
    resourceIdIn?: string[];
  },
>(filters: T, scope: AccessScope | undefined): T {
  if (scope === undefined || isUnscoped(scope)) return filters;

  assertRequestedValueInScope(scope, 'actorIds', filters.actorId);
  assertRequestedValueInScope(scope, 'resourceTypes', filters.resourceType);
  assertRequestedValueInScope(scope, 'resourceIds', filters.resourceId);

  const narrowed = { ...filters };
  if (scope.actorIds !== undefined && filters.actorId === undefined) {
    narrowed.actorIdIn = scope.actorIds;
  }
  if (scope.resourceTypes !== undefined && filters.resourceType === undefined) {
    narrowed.resourceTypeIn = scope.resourceTypes;
  }
  if (scope.resourceIds !== undefined && filters.resourceId === undefined) {
    narrowed.resourceIdIn = scope.resourceIds;
  }
  return narrowed;
}

/** Human-readable summary, safe to return from `/auth/whoami`. */
export function describeScope(scope: AccessScope | undefined): AccessScope & { unrestricted: boolean } {
  return { ...(scope ?? {}), unrestricted: isUnscoped(scope) };
}
