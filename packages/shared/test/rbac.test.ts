import { describe, it, expect } from 'vitest';
import { ROLES, PERMISSIONS, can, grantsFor, type Role, type Permission } from '../src/index.js';

/**
 * Phase 1 exit test — RBAC matrix + default-deny proof.
 * For each of the five roles against every protected permission, assert allowed/denied per the grant matrix;
 * and assert that an unknown role or an ungranted/unknown permission is denied.
 */

// Expected allow-set per role (the authoritative spec; `can()` must agree exactly).
const EXPECTED: Record<Role, ReadonlySet<Permission>> = {
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

describe('RBAC matrix (every role × every permission)', () => {
  for (const role of ROLES) {
    for (const perm of PERMISSIONS) {
      const shouldAllow = EXPECTED[role].has(perm);
      it(`${role} ${shouldAllow ? 'CAN' : 'cannot'} ${perm}`, () => {
        expect(can(role, perm)).toBe(shouldAllow);
      });
    }
  }
});

describe('default-deny', () => {
  it('denies an unknown role for every permission', () => {
    for (const perm of PERMISSIONS) {
      expect(can('superuser', perm)).toBe(false);
      expect(can('', perm)).toBe(false);
      expect(can(undefined, perm)).toBe(false);
      expect(can(null, perm)).toBe(false);
    }
  });

  it('denies an unknown/ungranted permission for every known role', () => {
    for (const role of ROLES) {
      expect(can(role, 'platform.take_over_everything')).toBe(false);
      expect(can(role, '')).toBe(false);
      expect(can(role, undefined)).toBe(false);
    }
  });

  it('SoD: Tester requests intrusive validation but can never approve it', () => {
    expect(can('tester', 'intrusive.validation.request')).toBe(true);
    expect(can('tester', 'intrusive.validation.approve')).toBe(false);
  });

  it('SoD: Administrator is not an engagement approver by default', () => {
    expect(can('administrator', 'intrusive.validation.approve')).toBe(false);
  });

  it('grantsFor(unknown role) is empty', () => {
    expect(grantsFor('nope').size).toBe(0);
  });
});

describe('grantsFor returns a defensive copy (Phase 1 item 7)', () => {
  it('mutating the returned set does not widen the internal authorization grants', () => {
    const grants = grantsFor('read_only_auditor');
    expect(grants.has('report.read')).toBe(true);
    // A caller tampers with the returned set, trying to grant themselves admin power and drop a permission.
    grants.add('platform.emergency_stop.global' as Permission);
    grants.delete('report.read' as Permission);
    // The live decision is unaffected: the internal matrix was never exposed by reference.
    expect(can('read_only_auditor', 'platform.emergency_stop.global')).toBe(false);
    expect(can('read_only_auditor', 'report.read')).toBe(true);
    // A fresh call reflects the true, untampered grants.
    const fresh = grantsFor('read_only_auditor');
    expect(fresh.has('platform.emergency_stop.global')).toBe(false);
    expect(fresh.has('report.read')).toBe(true);
  });

  it('two calls return independent set instances', () => {
    expect(grantsFor('tester')).not.toBe(grantsFor('tester'));
  });
});
