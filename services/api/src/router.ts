import { can, type Permission } from '@pentest/shared';

/**
 * Route table with per-route required permission. Authorization is DEFAULT-DENY at two levels:
 *  1. An unknown (method, path) → 404, never a fallthrough-allow.
 *  2. A known route requires an explicit permission; access is granted ONLY if `can(role, permission)` is true.
 * A public route (health) explicitly opts out of auth via `permission: null` — there is no implicit public access.
 */
export interface RouteDef {
  readonly method: string;
  readonly path: string;
  readonly permission: Permission | null; // null = explicitly public
}

// The registry is DEEP-FROZEN so it cannot be mutated at runtime (a mutated route table is an authorization bypass).
const ROUTES_INTERNAL: readonly RouteDef[] = Object.freeze(
  (
    [
      { method: 'GET', path: '/healthz', permission: null },
      { method: 'GET', path: '/engagements', permission: 'engagement.read' },
      { method: 'POST', path: '/engagements', permission: 'engagement.create' },
      { method: 'POST', path: '/engagements/scope', permission: 'engagement.scope.define' },
      {
        method: 'POST',
        path: '/intrusive/validation/request',
        permission: 'intrusive.validation.request',
      },
      {
        method: 'POST',
        path: '/intrusive/validation/approve',
        permission: 'intrusive.validation.approve',
      },
      { method: 'GET', path: '/audit', permission: 'audit.read' },
    ] satisfies RouteDef[]
  ).map((r) => Object.freeze(r)),
);

/** Return a shallow COPY of the route registry so callers cannot mutate the authoritative table. */
export function listRoutes(): RouteDef[] {
  return ROUTES_INTERNAL.map((r) => ({ ...r }));
}

/** Return a COPY of the route matching (method, path), or undefined. Never exposes the frozen internal object. */
export function matchRoute(method: string, path: string): RouteDef | undefined {
  const route = ROUTES_INTERNAL.find((r) => r.method === method && r.path === path);
  return route ? { ...route } : undefined;
}

/** Safe placeholder logged in place of a route when the request matched no known route. */
export const UNMATCHED_ROUTE = '(unmatched)';
/** Dev-only minter path — loggable (a fixed safe string) but never in the authorization table. */
export const DEV_TOKEN_PATH = '/dev/token';

/**
 * The ALLOWLIST of route strings that may appear in a log's `route` field: every known route template, the
 * dev-token path, plus the `UNMATCHED_ROUTE` sentinel. A raw URL, path, or query string is not in this set, so it
 * can never be logged.
 */
export const ROUTE_TEMPLATES: readonly string[] = Object.freeze([
  ...ROUTES_INTERNAL.map((r) => r.path),
  DEV_TOKEN_PATH,
  UNMATCHED_ROUTE,
]);

export type AuthzOutcome =
  | { readonly status: 200; readonly route: string; readonly permission: Permission | null }
  | { readonly status: 401; readonly route: string } // no authenticated identity for a protected route
  | { readonly status: 403; readonly route: string; readonly permission: Permission } // authenticated, not permitted
  | { readonly status: 404 }; // unknown route

/**
 * Pure authorization decision for a request. `role` is the caller's role (or undefined if unauthenticated). No side
 * effects. The returned `route` is the MATCHED route template (a known-safe string) — safe to log, unlike the raw URL.
 */
export function authorizeRequest(
  method: string,
  path: string,
  role: string | undefined,
): AuthzOutcome {
  const route = ROUTES_INTERNAL.find((r) => r.method === method && r.path === path);
  if (!route) return { status: 404 }; // unknown route → deny by default
  if (route.permission === null) return { status: 200, route: route.path, permission: null }; // explicitly public
  if (role === undefined) return { status: 401, route: route.path }; // protected route needs an identity
  if (!can(role, route.permission))
    return { status: 403, route: route.path, permission: route.permission };
  return { status: 200, route: route.path, permission: route.permission };
}
