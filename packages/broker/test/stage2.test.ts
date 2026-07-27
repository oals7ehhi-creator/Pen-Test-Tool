import { describe, it, expect } from 'vitest';
import { Duplex } from 'node:stream';
import { Buffer } from 'node:buffer';
import {
  mintGrant,
  computeSpecSha256,
  type GrantClaims,
  type RequestSpecContent,
} from '@pentest/spec';
import type { ScopeVersion, ScopeEntry } from '@pentest/scope';
import {
  runStage2,
  type Stage2Deps,
  type Stage2Input,
  type JobIdentity,
  type Connectors,
  type ReconstructContext,
} from '../src/index.js';

/**
 * Stage-2 orchestration (§7.1 steps 7–13). Proves the broker threads verify-grant → reconstruct → interlocks →
 * resolve/pin → connect/send → bounded-read → redirect-re-guard in the SECURITY-CRITICAL order: a denial at any step
 * short-circuits with a fixed {stage, reason}; a denial BEFORE step 12 opens NO socket (charge-before-egress); and a
 * 3xx is surfaced for a fresh spec+grant, never auto-followed.
 */

const KEY = new TextEncoder().encode('k'.repeat(32));
const ISS = 'scope-authority';
const AUD = 'egress-broker';
const NOW = 2_000_000;

const identity: JobIdentity = {
  tenantId: 'tenant-1',
  engagementId: 'eng-1',
  runId: 'run-1',
  jobId: 'job-1',
};

function makeSpec(over: Partial<RequestSpecContent> = {}): RequestSpecContent {
  return {
    engagementId: 'eng-1',
    scopeHash: 'a'.repeat(64),
    authorizationId: 'auth-1',
    requestClass: 'native',
    kind: 'http',
    checkDigest: null,
    toolTemplateDigest: null,
    headerSetDigest: 'h'.repeat(64),
    payloadDigest: null,
    wsFrameSetDigest: null,
    method: 'GET',
    canonicalUrl: 'https://example.com/api',
    canonicalHost: 'example.com',
    port: 443,
    scheme: 'https',
    canonicalPath: '/api',
    queryKeysCanonical: null,
    queryTemplateDigest: null,
    queryValueBinding: null,
    queryValueDigest: null,
    sessionDigest: null,
    approvalRequired: false,
    ...over,
  };
}

function claimsFor(spec: RequestSpecContent): GrantClaims {
  return {
    ...identity,
    authorizationId: 'auth-1',
    scopeHash: 'a'.repeat(64),
    specSha256: computeSpecSha256(spec),
    requestClass: 'native',
  };
}

async function grantFor(spec: RequestSpecContent, jti = 'jti-1'): Promise<string> {
  return mintGrant({
    claims: claimsFor(spec),
    key: KEY,
    kid: 'k',
    issuer: ISS,
    audience: AUD,
    ttlSeconds: 30,
    nowSeconds: NOW,
    jti,
  });
}

/** A socket-like Duplex that yields a canned response on read and discards writes. */
function cannedSocket(response: string): Duplex {
  return new Duplex({
    read() {
      this.push(Buffer.from(response, 'utf8'));
      this.push(null);
    },
    write(_chunk, _enc, cb) {
      cb();
    },
  });
}

const scope = (...entries: ScopeEntry[]): ScopeVersion => ({ entries });

const reconstructCtx = (over: Partial<ReconstructContext> = {}): ReconstructContext => ({
  fetchHeaderSet: () => Promise.resolve({ headers: [{ name: 'accept', value: '*/*' }] }),
  fetchPayload: () => Promise.resolve(null),
  fetchQueryTemplate: () => Promise.resolve(null),
  resolveSession: () => Promise.resolve(null),
  resolveQueryValues: () => Promise.resolve(null),
  queryValueHmacKey: KEY,
  ...over,
});

/** Deps that thread a successful request through to `response`, with a hook to observe/deny each step. */
function makeDeps(
  over: {
    response?: string;
    resolveTo?: readonly string[];
    onConnect?: () => void;
    reconstruct?: Partial<ReconstructContext>;
    beforeEgress?: Stage2Deps['beforeEgress'];
  } = {},
): { deps: Stage2Deps; connectCount: () => number } {
  let connects = 0;
  const conn = (): Duplex => {
    connects++;
    over.onConnect?.();
    return cannedSocket(over.response ?? 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi');
  };
  const connectors: Connectors = { tcp: conn, tls: conn };
  const deps: Stage2Deps = {
    grantVerify: { key: KEY, issuer: ISS, audience: AUD, nowSeconds: NOW, consumeJti: jtiStore() },
    reconstruct: reconstructCtx(over.reconstruct),
    ...(over.beforeEgress !== undefined ? { beforeEgress: over.beforeEgress } : {}),
    resolve: {
      scope: scope({
        class: 'domain',
        hostAscii: 'example.com',
        wildcard: false,
        includeSubdomains: false,
      }),
      resolve: () => Promise.resolve(over.resolveTo ?? ['93.184.216.34']),
    },
    connectors,
    read: { maxBodyBytes: 1024 },
    redirect: {
      scope: scope({
        class: 'domain',
        hostAscii: 'example.com',
        wildcard: true,
        includeSubdomains: true,
      }),
      maxHops: 5,
    },
  };
  return { deps, connectCount: () => connects };
}

function jtiStore(): (jti: string) => boolean {
  const used = new Set<string>();
  return (jti) => (used.has(jti) ? false : (used.add(jti), true));
}

async function input(over: Partial<Stage2Input> = {}): Promise<Stage2Input> {
  const spec = over.spec ?? makeSpec();
  return { identity, grantToken: over.grantToken ?? (await grantFor(spec)), spec, ...over };
}

describe('runStage2 — happy path', () => {
  it('threads grant → reconstruct → resolve/pin → connect/send → bounded read to a response', async () => {
    const { deps, connectCount } = makeDeps();
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.claims).toMatchObject(identity);
      expect(out.pinnedIp).toBe('93.184.216.34');
      expect(out.response.statusCode).toBe(200);
      expect(Buffer.from(out.response.body).toString('utf8')).toBe('hi');
      expect(out.redirect).toBeNull();
    }
    expect(connectCount()).toBe(1);
  });
});

describe('runStage2 — denials short-circuit with a fixed {stage, reason}', () => {
  it('DENY at ingress on a wrong-key grant (no reconstruct, no egress)', async () => {
    const { deps, connectCount } = makeDeps();
    const bad = {
      ...deps,
      grantVerify: { ...deps.grantVerify, key: new TextEncoder().encode('z'.repeat(32)) },
    };
    const out = await runStage2(await input(), bad);
    expect(out).toMatchObject({ ok: false, stage: 'ingress' });
    expect(connectCount()).toBe(0);
  });

  it('DENY at ingress on a spec that does not match the grant', async () => {
    const { deps } = makeDeps();
    // grant minted for the default spec, but a DIFFERENT spec is presented ⇒ spec_sha256 mismatch.
    const granted = makeSpec();
    const other = makeSpec({ canonicalPath: '/other', canonicalUrl: 'https://example.com/other' });
    const out = await runStage2(
      { identity, grantToken: await grantFor(granted), spec: other },
      deps,
    );
    expect(out).toMatchObject({ ok: false, stage: 'ingress', reason: 'spec_mismatch' });
  });

  it('DENY at ingress on a mismatched job identity', async () => {
    const { deps, connectCount } = makeDeps();
    const spec = makeSpec();
    const out = await runStage2(
      { identity: { ...identity, jobId: 'job-2' }, grantToken: await grantFor(spec), spec },
      deps,
    );
    expect(out).toMatchObject({ ok: false, stage: 'ingress', reason: 'identity_mismatch' });
    expect(connectCount()).toBe(0);
  });

  it('DENY at reconstruct when the header-set is missing (no egress)', async () => {
    const { deps, connectCount } = makeDeps({
      reconstruct: { fetchHeaderSet: () => Promise.resolve(null) },
    });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'reconstruct', reason: 'header_set_not_found' });
    expect(connectCount()).toBe(0);
  });

  it('DENY at the interlock hook — and NO socket is opened (charge-before-egress)', async () => {
    const { deps, connectCount } = makeDeps({
      beforeEgress: () => {
        throw new Error('budget_exhausted');
      },
    });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'interlock' });
    expect(connectCount()).toBe(0);
  });

  it('DENY at resolve when the host resolves to a forbidden address — and NO socket is opened', async () => {
    const { deps, connectCount } = makeDeps({ resolveTo: ['169.254.169.254'] });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({
      ok: false,
      stage: 'resolve',
      reason: 'network_guard:cloud_metadata',
    });
    expect(connectCount()).toBe(0);
  });

  it('refuses the whole resolution when ONE resolved address is forbidden (rebinding) — no egress', async () => {
    const { deps, connectCount } = makeDeps({ resolveTo: ['93.184.216.34', '169.254.169.254'] });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'resolve' });
    expect(connectCount()).toBe(0);
  });

  it('DENY at send when the connector fails to create the socket', async () => {
    const { deps } = makeDeps();
    const boom: Connectors = {
      tcp: () => {
        throw new Error('ECONNREFUSED');
      },
      tls: () => {
        throw new Error('ECONNREFUSED');
      },
    };
    const out = await runStage2(await input(), { ...deps, connectors: boom });
    expect(out).toMatchObject({ ok: false, stage: 'send' });
  });

  it('DENY at read on a malformed response', async () => {
    const { deps, connectCount } = makeDeps({ response: 'NOT-HTTP\r\n\r\n' });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'read' });
    expect(connectCount()).toBe(1); // the socket WAS opened (we reached step 12) before the response failed
  });

  it('maps the scheme to the transport: http ⇒ plain TCP, wss ⇒ TLS', async () => {
    const dial = (): { connectors: Connectors; used: () => string[] } => {
      const calls: string[] = [];
      const mk = (kind: string) => (): Duplex => {
        calls.push(kind);
        return cannedSocket('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi');
      };
      return { connectors: { tcp: mk('tcp'), tls: mk('tls') }, used: () => calls };
    };

    const httpSpec = makeSpec({ scheme: 'http', port: 80, canonicalUrl: 'http://example.com/api' });
    const h = dial();
    const { deps: d1 } = makeDeps();
    const outH = await runStage2(
      { identity, grantToken: await grantFor(httpSpec), spec: httpSpec },
      { ...d1, connectors: h.connectors },
    );
    expect(outH.ok).toBe(true);
    expect(h.used()).toEqual(['tcp']);

    const wsSpec = makeSpec({
      kind: 'websocket',
      scheme: 'wss',
      canonicalUrl: 'wss://example.com/api',
    });
    const w = dial();
    const { deps: d2 } = makeDeps();
    const outW = await runStage2(
      { identity, grantToken: await grantFor(wsSpec), spec: wsSpec },
      { ...d2, connectors: w.connectors },
    );
    expect(outW.ok).toBe(true);
    expect(w.used()).toEqual(['tls']);
  });

  it('the interlock hook receives the reconstructed request and claims (order proof)', async () => {
    let seen: { host: string; job: string } | null = null;
    const { deps } = makeDeps({
      beforeEgress: ({ claims, request }) => {
        seen = { host: request.host, job: claims.jobId };
      },
    });
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(true);
    expect(seen).toEqual({ host: 'example.com', job: 'job-1' });
  });
});

describe('runStage2 — redirects are surfaced, never auto-followed', () => {
  const redirectResponse = (location: string): string =>
    `HTTP/1.1 302 Found\r\nLocation: ${location}\r\nContent-Length: 0\r\n\r\n`;

  it('re-guards an in-scope redirect and returns the follow decision (one connect, not followed)', async () => {
    const { deps, connectCount } = makeDeps({
      response: redirectResponse('https://api.example.com/v2'),
    });
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.response.statusCode).toBe(302);
      expect(out.redirect?.follow).toBe(true);
      if (out.redirect?.follow) {
        expect(out.redirect.next.host).toMatchObject({
          kind: 'domain',
          hostAscii: 'api.example.com',
        });
      }
    }
    expect(connectCount()).toBe(1); // NOT auto-followed — only the original request was dialed
  });

  it('refuses an out-of-scope redirect (follow:false), still one connect', async () => {
    const { deps, connectCount } = makeDeps({ response: redirectResponse('https://evil.test/') });
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(true);
    if (out.ok && out.redirect) {
      expect(out.redirect.follow).toBe(false);
    }
    expect(connectCount()).toBe(1);
  });

  it('a 302 with no Location yields a null redirect decision', async () => {
    const { deps } = makeDeps({ response: 'HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n' });
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.redirect).toBeNull();
  });
});
