/**
 * The five canonical platform roles (Phase 0 doc `09-rbac-matrix.md`). This list is closed: an identity
 * whose role is not one of these is treated as having NO permissions (default-deny).
 */
export const ROLES = [
  'administrator',
  'engagement_manager',
  'tester',
  'reviewer',
  'read_only_auditor',
] as const;

export type Role = (typeof ROLES)[number];

const ROLE_SET: ReadonlySet<string> = new Set(ROLES);

/** Narrowing guard: true only for one of the five known roles. Anything else is untrusted / unknown. */
export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && ROLE_SET.has(value);
}
