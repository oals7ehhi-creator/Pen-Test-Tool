import { type Role, isRole } from './roles.js';
import { type Permission } from './permissions.js';

/**
 * DEFAULT-DENY role→permission grant matrix. A role has EXACTLY the permissions listed here and nothing else.
 * Mirrors Phase 0 `09-rbac-matrix.md`. Notes on separation of duties encoded here:
 *  - Administrator holds platform power but is NOT an engagement approver by default (no intrusive approve).
 *  - Tester requests intrusive validation but can never approve it (SoD from the approver).
 *  - Reviewer is an eligible approver for intrusive validation but does NOT execute scans (SoD from Tester).
 *  - Read-only Auditor can read reports/audit and nothing else.
 */
const roleGrants: Readonly<Record<Role, ReadonlySet<Permission>>> = {
  administrator: new Set<Permission>([
    'platform.users.manage',
    'platform.tools.manage',
    'platform.emergency_stop.global',
    'audit.read',
    'report.read',
  ]),
  engagement_manager: new Set<Permission>([
    'engagement.create',
    'engagement.read',
    'engagement.scope.define',
    'engagement.authorization.attest',
    'intrusive.validation.approve',
    'report.read',
    'audit.read',
  ]),
  tester: new Set<Permission>([
    'engagement.read',
    'scan.passive.run',
    'scan.safe_active.run',
    'intrusive.validation.request',
    'report.read',
  ]),
  reviewer: new Set<Permission>([
    'engagement.read',
    'finding.triage',
    'intrusive.validation.approve',
    'report.read',
    'audit.read',
  ]),
  read_only_auditor: new Set<Permission>(['report.read', 'audit.read']),
};

/**
 * The single authorization decision point. Returns true ONLY when `role` is one of the five known roles AND
 * that role has been explicitly granted `permission`. An unknown role, an unknown permission, or any value that
 * is not in the grant matrix returns false. There is no code path that returns true by default.
 */
export function can(role: unknown, permission: unknown): boolean {
  if (!isRole(role)) return false; // unknown/absent role → deny
  const grants = roleGrants[role];
  return grants.has(permission as Permission);
}

/** All permissions explicitly granted to a known role (empty for unknown roles). For introspection/tests. */
export function grantsFor(role: unknown): ReadonlySet<Permission> {
  return isRole(role) ? roleGrants[role] : new Set<Permission>();
}
