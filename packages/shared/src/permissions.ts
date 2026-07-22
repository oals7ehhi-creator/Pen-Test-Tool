/**
 * Permissions are fine-grained, action-level capabilities. This is the Phase 1 foundational subset; later
 * phases extend it. Authorization is DEFAULT-DENY: a permission is reachable only if it is explicitly granted
 * to the caller's role in the matrix below (`roleGrants`). There is no wildcard and no implicit inheritance.
 */
export const PERMISSIONS = [
  // platform administration
  'platform.users.manage',
  'platform.tools.manage',
  'platform.emergency_stop.global',
  // engagement lifecycle
  'engagement.create',
  'engagement.read',
  'engagement.scope.define',
  'engagement.authorization.attest', // request/attest written authorization
  // execution
  'scan.passive.run',
  'scan.safe_active.run',
  'intrusive.validation.request',
  'intrusive.validation.approve', // dual-control approver side
  // findings & oversight
  'finding.triage',
  'report.read',
  'audit.read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const PERMISSION_SET: ReadonlySet<string> = new Set(PERMISSIONS);

export function isPermission(value: unknown): value is Permission {
  return typeof value === 'string' && PERMISSION_SET.has(value);
}
