import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { ROLES, type Role } from '@pentest/shared';
import { SignJWT } from 'jose';
import { listRoutes } from '../src/router.js';
import { SESSION_COOKIE } from '../src/auth.js';
import {
  invoke,
  requestLog,
  signIdentity,
  testAuthContext,
  testSigningKey,
  TEST_ISSUER,
  TEST_AUDIENCE,
  FIXED_NOW,
} from './factories.js';

/**
 * End-to-end authentication + authorization through the real HTTP handler, using SIGNED SESSIONS (never role
 * injection). Covers: the full authenticated role × protected-route RBAC matrix; header/query/body role-spoof
 * attempts; every token-failure mode; the gated dev token minter; cookie auth; and log secrecy.
 */

// The authoritative permitted-role set per protected route (mirrors Phase 0 RBAC; independent of implementation).
const PERMITTED: Record<string, ReadonlyArray<Role>> = {
  'GET /engagements': ['engagement_manager', 'tester', 'reviewer'],
  'POST /engagements': ['engagement_manager'],
  'POST /engagements/scope': ['engagement_manager'],
  'POST /intrusive/validation/request': ['tester'],
  'POST /intrusive/validation/approve': ['engagement_manager', 'reviewer'],
  'GET /audit': ['administrator', 'engagement_manager', 'reviewer', 'read_only_auditor'],
};

describe('health is the only public route', () => {
  it('GET /healthz needs no identity', async () => {
    const r = await invoke({ method: 'GET', path: '/healthz' });
    expect(r.status).toBe(200);
    expect(requestLog(r).fields).toEqual({ method: 'GET', route: '/healthz', status: 200 });
  });

  it('every protected route without a session is 401', async () => {
    for (const route of listRoutes()) {
      if (route.permission === null) continue;
      const r = await invoke({ method: route.method, path: route.path });
      expect(r.status).toBe(401);
      expect(requestLog(r).fields.reason).toBe('missing');
    }
  });
});

describe('authenticated RBAC matrix — every role × every protected route (via signed sessions)', () => {
  for (const route of listRoutes()) {
    if (route.permission === null) continue;
    const key = `${route.method} ${route.path}`;
    const allowed = new Set(PERMITTED[key]);
    for (const role of ROLES) {
      const expected = allowed.has(role) ? 501 : 403; // authorized→business stub (501); else forbidden (403)
      it(`${role} → ${route.method} ${route.path} = ${expected}`, async () => {
        const token = await signIdentity(role);
        const r = await invoke({ method: route.method, path: route.path, token });
        expect(r.status).toBe(expected);
        if (expected === 403) expect(requestLog(r).fields.reason).toBe('forbidden');
      });
    }
  }

  it('an authenticated identity carries a real per-request correlation id (never "root")', async () => {
    const token = await signIdentity('administrator');
    const r = await invoke({ method: 'GET', path: '/audit', token });
    expect(requestLog(r).correlationId).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('role comes ONLY from verified claims — spoofing is ignored', () => {
  it('a header / query / body role cannot grant access without a token', async () => {
    const r = await invoke({
      method: 'GET',
      path: '/audit',
      headers: { 'x-dev-role': 'administrator', 'x-role': 'administrator' },
    });
    expect(r.status).toBe(401); // no verified session ⇒ unauthenticated regardless of headers
  });

  it('a header cannot escalate a verified lower-privileged role', async () => {
    const testerToken = await signIdentity('tester');
    // Tester lacks audit.read; a spoofed admin header must NOT change the verified role.
    const r = await invoke({
      method: 'GET',
      path: '/audit',
      token: testerToken,
      headers: { 'x-dev-role': 'administrator', 'x-dev-mint-role': 'administrator' },
    });
    expect(r.status).toBe(403);
  });

  it('a query-string role is ignored (route matched by path only)', async () => {
    const r = await invoke({ method: 'GET', path: '/audit?role=administrator' });
    expect(r.status).toBe(401);
  });
});

describe('token failures through the handler → 401 with a safe reason', () => {
  const cases: Array<{ name: string; make: () => Promise<string> }> = [
    { name: 'bad_signature', make: () => signIdentity('administrator', {}, otherKey()) },
    {
      name: 'expired',
      make: () =>
        signIdentity('administrator', {
          now: FIXED_NOW - 60 * 60,
          sessionStart: FIXED_NOW - 60 * 60,
        }),
    },
    { name: 'wrong_issuer', make: () => signIdentity('administrator', { issuer: 'evil' }) },
    { name: 'wrong_audience', make: () => signIdentity('administrator', { audience: 'evil' }) },
    {
      name: 'absolute_exceeded',
      make: () => signIdentity('administrator', { sessionStart: FIXED_NOW - 13 * 3600 }),
    },
  ];
  for (const c of cases) {
    it(c.name, async () => {
      const r = await invoke({ method: 'GET', path: '/audit', token: await c.make() });
      expect(r.status).toBe(401);
      expect(requestLog(r).fields.reason).toBe(c.name);
    });
  }

  it('algorithm confusion (alg:none) is rejected', async () => {
    const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
    const none =
      b64({ alg: 'none' }) +
      '.' +
      b64({
        sub: 'u',
        role: 'administrator',
        sid: 's',
        sat: FIXED_NOW,
        iat: FIXED_NOW,
        exp: FIXED_NOW + 60,
        iss: TEST_ISSUER,
        aud: TEST_AUDIENCE,
      }) +
      '.';
    const r = await invoke({ method: 'GET', path: '/audit', token: none });
    expect(r.status).toBe(401);
    expect(requestLog(r).fields.reason).toBe('wrong_algorithm');
  });

  it('an unknown role in an otherwise-valid token is rejected', async () => {
    const token = await new SignJWT({ role: 'superuser', sid: 's', sat: FIXED_NOW })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u')
      .setIssuer(TEST_ISSUER)
      .setAudience(TEST_AUDIENCE)
      .setIssuedAt(FIXED_NOW)
      .setNotBefore(FIXED_NOW)
      .setExpirationTime(FIXED_NOW + 60)
      .sign(testSigningKey().key);
    const r = await invoke({ method: 'GET', path: '/audit', token });
    expect(r.status).toBe(401);
    expect(requestLog(r).fields.reason).toBe('unknown_role');
  });

  it('a malformed token is rejected', async () => {
    const r = await invoke({ method: 'GET', path: '/audit', token: 'not-a-jwt' });
    expect(r.status).toBe(401);
    expect(requestLog(r).fields.reason).toBe('malformed');
  });

  it('an empty session cookie value is treated as no token (401 missing)', async () => {
    const r = await invoke({
      method: 'GET',
      path: '/audit',
      headers: { cookie: `${SESSION_COOKIE}=; theme=dark` },
    });
    expect(r.status).toBe(401);
    expect(requestLog(r).fields.reason).toBe('missing');
  });
});

describe('routing', () => {
  it('an unknown route is 404 (default-deny: not a silent pass)', async () => {
    const r = await invoke({ method: 'GET', path: '/no/such/route' });
    expect(r.status).toBe(404);
    expect(requestLog(r).fields).toEqual({ method: 'GET', route: '(unmatched)', status: 404 });
  });
});

describe('dev token minter (gated, non-production only)', () => {
  it('is 404 (structurally unavailable) when disabled', async () => {
    const r = await invoke({
      method: 'POST',
      path: '/dev/token',
      headers: { 'x-dev-mint-role': 'tester' },
    });
    expect(r.status).toBe(404);
  });

  it('mints a signed session usable on a permitted route, and sets an HttpOnly cookie', async () => {
    const ctx = testAuthContext({ devMinterEnabled: true });
    const minted = await invoke({
      method: 'POST',
      path: '/dev/token',
      headers: { 'x-dev-mint-role': 'tester' },
      ctx,
    });
    expect(minted.status).toBe(200);
    const token = (JSON.parse(minted.body) as { token: string }).token;
    expect(token.split('.')).toHaveLength(3);
    expect(minted.headers['set-cookie']).toContain('HttpOnly');
    // Use the minted token on a tester-permitted route.
    const r = await invoke({ method: 'GET', path: '/engagements', token, ctx });
    expect(r.status).toBe(501); // authorized
  });

  it('rejects an unknown role (400)', async () => {
    const ctx = testAuthContext({ devMinterEnabled: true });
    const r = await invoke({
      method: 'POST',
      path: '/dev/token',
      headers: { 'x-dev-mint-role': 'superuser' },
      ctx,
    });
    expect(r.status).toBe(400);
  });
});

describe('cookie-carried session is accepted', () => {
  it('a valid token in the session cookie authorizes like a Bearer token', async () => {
    const token = await signIdentity('reviewer');
    const r = await invoke({
      method: 'GET',
      path: '/audit',
      headers: { cookie: `${SESSION_COOKIE}=${token}; theme=dark` },
    });
    expect(r.status).toBe(501); // reviewer has audit.read
  });
});

describe('no token, cookie, Authorization, or API key ever reaches the logs', () => {
  it('logs only method/route/status(/reason) — never secrets', async () => {
    const token = await signIdentity('tester');
    const apiKey = 'planted-sentinel-not-a-real-secret';
    const ctx = testAuthContext({ devMinterEnabled: true });
    // A request carrying a Bearer token, a session cookie, and an API-key header.
    const r = await invoke({
      method: 'GET',
      path: '/engagements',
      token,
      headers: {
        cookie: `${SESSION_COOKIE}=${token}`,
        'x-api-key': apiKey,
        authorization: `Bearer ${token}`,
      },
      ctx,
    });
    // A dev-mint response that emits a Set-Cookie header.
    const minted = await invoke({
      method: 'POST',
      path: '/dev/token',
      headers: { 'x-dev-mint-role': 'tester' },
      ctx,
    });

    const logs = [...r.lines, ...minted.lines].join('\n');
    expect(logs).not.toContain(token);
    expect(logs).not.toContain(apiKey);
    expect(logs).not.toContain('Bearer');
    expect(logs).not.toContain('Set-Cookie');
    expect(logs).not.toContain(SESSION_COOKIE);
    // The one request record carries exactly the allowlisted fields.
    expect(requestLog(r).fields).toEqual({ method: 'GET', route: '/engagements', status: 501 });
  });
});

// A distinct signing key (different from the test key) → forces a signature-verification failure. Its material is
// DERIVED from a fixed seed (not a committed literal), so no secret is committed to the repository.
function otherKey(): ReturnType<typeof testSigningKey> {
  return {
    kid: 'k_other',
    ephemeral: false,
    key: new TextEncoder().encode(
      createHash('sha256').update('auth-e2e-other-key-seed').digest('base64url'),
    ),
  };
}
