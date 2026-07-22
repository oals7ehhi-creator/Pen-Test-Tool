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

export const ROUTES: readonly RouteDef[] = [
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
];

export type AuthzOutcome =
  | { readonly status: 200; readonly permission: Permission | null }
  | { readonly status: 401 } // no authenticated identity for a protected route
  | { readonly status: 403; readonly permission: Permission } // authenticated but not permitted
  | { readonly status: 404 }; // unknown route

/**
 * Pure authorization decision for a request. `role` is the caller's role (or undefined if unauthenticated).
 * No side effects; used directly by the server handler and by tests.
 */
export function authorizeRequest(
  method: string,
  path: string,
  role: string | undefined,
): AuthzOutcome {
  const route = ROUTES.find((r) => r.method === method && r.path === path);
  if (!route) return { status: 404 }; // unknown route → deny by default
  if (route.permission === null) return { status: 200, permission: null }; // explicitly public
  if (role === undefined) return { status: 401 }; // protected route needs an identity
  if (!can(role, route.permission)) return { status: 403, permission: route.permission }; // default-deny
  return { status: 200, permission: route.permission };
}
