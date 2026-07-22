import { describe, it, expect } from 'vitest';
import { authorizeRequest, ROUTES } from '../src/router.js';
import { ROLES } from '@pentest/shared';

/**
 * Phase 1 exit test — default-deny authorization at the route layer, for every role × every protected route.
 */

describe('route authorization', () => {
  it('health is public (no identity required)', () => {
    expect(authorizeRequest('GET', '/healthz', undefined).status).toBe(200);
  });

  it('unknown route is 404 (no fallthrough-allow)', () => {
    expect(authorizeRequest('GET', '/definitely/not/a/route', 'administrator').status).toBe(404);
  });

  it('protected route without identity is 401', () => {
    expect(authorizeRequest('GET', '/engagements', undefined).status).toBe(401);
  });

  it('unknown role is denied on every protected route', () => {
    for (const r of ROUTES) {
      if (r.permission === null) continue;
      expect(authorizeRequest(r.method, r.path, 'superuser').status).toBe(403);
    }
  });

  it('each protected route grants exactly the roles that hold its permission, denies the rest', () => {
    const permittedRoles: Record<string, ReadonlyArray<string>> = {
      'GET /engagements': ['engagement_manager', 'tester', 'reviewer'],
      'POST /engagements': ['engagement_manager'],
      'POST /engagements/scope': ['engagement_manager'],
      'POST /intrusive/validation/request': ['tester'],
      'POST /intrusive/validation/approve': ['engagement_manager', 'reviewer'],
      'GET /audit': ['administrator', 'engagement_manager', 'reviewer', 'read_only_auditor'],
    };
    for (const r of ROUTES) {
      if (r.permission === null) continue;
      const key = `${r.method} ${r.path}`;
      const allowed = new Set(permittedRoles[key]);
      for (const role of ROLES) {
        const expected = allowed.has(role) ? 200 : 403;
        expect(authorizeRequest(r.method, r.path, role).status).toBe(expected);
      }
    }
  });
});
