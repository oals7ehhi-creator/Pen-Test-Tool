import { describe, it, expect } from 'vitest';
import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import {
  signSession,
  verifySession,
  SessionError,
  IDLE_MAX_SECONDS,
  ABSOLUTE_MAX_SECONDS,
  type Role,
} from '../src/index.js';

/**
 * Session verification battery: a valid token yields the claimed identity; every tampering / confusion / timing /
 * claim-shape attack is rejected with a typed, secret-free `SessionError`. The accepted algorithm, issuer, and
 * audience are pinned; role comes exclusively from verified claims.
 */

const KEY = new TextEncoder().encode(
  createHash('sha256').update('session-test-key').digest('base64url'),
);
const OTHER_KEY = new TextEncoder().encode(
  createHash('sha256').update('session-other-key').digest('base64url'),
);
const ISS = 'pentest-tool';
const AUD = 'pentest-api';
const NOW = 1_700_000_000;
const SECRET = 'top-secret-must-not-leak-in-errors';

const good = (over: Partial<Parameters<typeof signSession>[0]> = {}): Promise<string> =>
  signSession({
    key: KEY,
    issuer: ISS,
    audience: AUD,
    subject: 'user:1',
    role: 'tester',
    sid: 'sid-1',
    sessionStart: NOW,
    ttlSeconds: 15 * 60,
    now: NOW,
    ...over,
  });

const verify = (
  token: string,
  over: Partial<Parameters<typeof verifySession>[0]> = {},
): Promise<unknown> =>
  verifySession({ token, key: KEY, issuer: ISS, audience: AUD, now: NOW, ...over });

async function reasonOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'NO_ERROR';
  } catch (e) {
    if (e instanceof SessionError) return e.reason;
    return `UNEXPECTED:${String(e)}`;
  }
}

describe('verifySession — happy path', () => {
  it('returns the identity from verified claims', async () => {
    const id = await verifySession({
      token: await good(),
      key: KEY,
      issuer: ISS,
      audience: AUD,
      now: NOW,
    });
    expect(id).toEqual({ sub: 'user:1', role: 'tester', sid: 'sid-1' });
  });

  it('accepts each of the five roles', async () => {
    const roles: Role[] = [
      'administrator',
      'engagement_manager',
      'tester',
      'reviewer',
      'read_only_auditor',
    ];
    for (const role of roles) {
      const id = await verifySession({
        token: await good({ role }),
        key: KEY,
        issuer: ISS,
        audience: AUD,
        now: NOW,
      });
      expect((id as { role: string }).role).toBe(role);
    }
  });
});

describe('verifySession — rejections (each returns a typed reason, never leaking the token)', () => {
  it('missing token', async () => {
    expect(await reasonOf(verify(''))).toBe('missing');
    expect(
      await reasonOf(
        verifySession({ token: undefined, key: KEY, issuer: ISS, audience: AUD, now: NOW }),
      ),
    ).toBe('missing');
  });

  it('malformed token', async () => {
    expect(await reasonOf(verify('not.a.jwt'))).toBe('malformed');
    expect(await reasonOf(verify('garbage'))).toBe('malformed');
  });

  it('invalid signature (signed with a different key)', async () => {
    expect(await reasonOf(verify(await good({ key: OTHER_KEY })))).toBe('bad_signature');
  });

  it('algorithm confusion: alg:none and a non-HS256 alg are rejected', async () => {
    const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
    const none =
      b64({ alg: 'none' }) +
      '.' +
      b64({
        sub: 'user:1',
        role: 'tester',
        sid: 's',
        sat: NOW,
        iat: NOW,
        nbf: NOW,
        exp: NOW + 60,
        iss: ISS,
        aud: AUD,
      }) +
      '.';
    expect(await reasonOf(verify(none))).toBe('wrong_algorithm');
    const hs384 = await new SignJWT({ role: 'tester', sid: 's', sat: NOW })
      .setProtectedHeader({ alg: 'HS384' })
      .setSubject('user:1')
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt(NOW)
      .setNotBefore(NOW)
      .setExpirationTime(NOW + 60)
      .sign(KEY);
    expect(await reasonOf(verify(hs384))).toBe('wrong_algorithm');
  });

  it('expired token', async () => {
    expect(await reasonOf(verify(await good(), { now: NOW + 16 * 60 }))).toBe('expired');
  });

  it('not-yet-valid (future-dated nbf)', async () => {
    expect(await reasonOf(verify(await good({ now: NOW + 1000 }), { now: NOW }))).toBe(
      'not_yet_valid',
    );
  });

  it('future issued-at (iat ahead of now, nbf ok)', async () => {
    const tok = await new SignJWT({ role: 'tester', sid: 's', sat: NOW })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user:1')
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt(NOW + 5000)
      .setNotBefore(NOW - 10)
      .setExpirationTime(NOW + 60)
      .sign(KEY);
    expect(await reasonOf(verify(tok))).toBe('future_issued');
  });

  it('wrong issuer / wrong audience', async () => {
    expect(await reasonOf(verify(await good({ issuer: 'evil' })))).toBe('wrong_issuer');
    expect(await reasonOf(verify(await good({ audience: 'evil' })))).toBe('wrong_audience');
  });

  it('idle window exceeded (token lifetime > 30 min)', async () => {
    const tok = await new SignJWT({ role: 'tester', sid: 's', sat: NOW })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user:1')
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt(NOW)
      .setNotBefore(NOW)
      .setExpirationTime(NOW + IDLE_MAX_SECONDS + 120)
      .sign(KEY);
    expect(await reasonOf(verify(tok))).toBe('idle_exceeded');
  });

  it('absolute session lifetime exceeded (session started > 12 h ago)', async () => {
    expect(
      await reasonOf(verify(await good({ sessionStart: NOW - ABSOLUTE_MAX_SECONDS - 60 }))),
    ).toBe('absolute_exceeded');
  });

  it('no subject / unknown role / missing sid', async () => {
    const claims = (extra: Record<string, unknown>): SignJWT =>
      new SignJWT({ sid: 's', sat: NOW, ...extra })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(ISS)
        .setAudience(AUD)
        .setIssuedAt(NOW)
        .setNotBefore(NOW)
        .setExpirationTime(NOW + 60);
    expect(await reasonOf(verify(await claims({ role: 'tester' }).sign(KEY)))).toBe('no_subject'); // no sub
    expect(
      await reasonOf(verify(await claims({ role: 'superuser' }).setSubject('u').sign(KEY))),
    ).toBe('unknown_role');
    const noSid = await new SignJWT({ role: 'tester', sat: NOW })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u')
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt(NOW)
      .setNotBefore(NOW)
      .setExpirationTime(NOW + 60)
      .sign(KEY);
    expect(await reasonOf(verify(noSid))).toBe('malformed'); // missing sid
  });

  it('errors never contain the token or a secret', async () => {
    const tokenWithSecret = await good({ subject: SECRET });
    let msg = '';
    try {
      await verify(tokenWithSecret, { key: OTHER_KEY }); // bad signature
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toBe('session rejected: bad_signature');
    expect(msg).not.toContain(SECRET);
    expect(msg).not.toContain(tokenWithSecret);
  });
});

describe('verifySession — absolute-lifetime cannot be reset by claim manipulation', () => {
  // Craft tokens directly so we control iat/nbf/exp/sat independently of signSession.
  const craft = (claims: { iat: number; nbf: number; exp: number; sat: number }): Promise<string> =>
    new SignJWT({ role: 'tester', sid: 's', sat: claims.sat })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user:1')
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt(claims.iat)
      .setNotBefore(claims.nbf)
      .setExpirationTime(claims.exp)
      .sign(KEY);

  it('rejects a session that claims to have STARTED AFTER it was issued (sat > iat)', async () => {
    // iat in the past, sat = now (> iat): not future-dated, but chronologically impossible.
    const tok = await craft({ iat: NOW - 100, nbf: NOW - 100, exp: NOW + 60, sat: NOW });
    expect(await reasonOf(verify(tok))).toBe('bad_chronology');
  });

  it('rejects a fresh idle-valid token whose expiry would run PAST the 12 h absolute deadline', async () => {
    // Session started 11h50m ago; a brand-new 30-min token is idle-valid and not yet absolutely expired, but its
    // expiry (now+30m) lies beyond the absolute deadline (sat+12h = now+10m) → must be refused.
    const sat = NOW - (ABSOLUTE_MAX_SECONDS - 600);
    const tok = await craft({ iat: NOW, nbf: NOW, exp: NOW + 30 * 60, sat });
    expect(await reasonOf(verify(tok))).toBe('absolute_exceeded');
  });

  it('still accepts a token that starts at issuance and expires within both windows', async () => {
    const tok = await craft({ iat: NOW, nbf: NOW, exp: NOW + 15 * 60, sat: NOW });
    await expect(
      verifySession({ token: tok, key: KEY, issuer: ISS, audience: AUD, now: NOW }),
    ).resolves.toBeDefined();
  });
});

describe('signSession — clamps idle lifetime', () => {
  it('never mints a token whose lifetime exceeds the 30-minute cap', async () => {
    const tok = await good({ ttlSeconds: 10 * 60 * 60 }); // ask for 10h
    // Verifiable now, but expired just after the 30-min cap (proving the clamp).
    await expect(
      verifySession({ token: tok, key: KEY, issuer: ISS, audience: AUD, now: NOW }),
    ).resolves.toBeDefined();
    expect(await reasonOf(verify(tok, { now: NOW + IDLE_MAX_SECONDS + 30 }))).toBe('expired');
  });
});
