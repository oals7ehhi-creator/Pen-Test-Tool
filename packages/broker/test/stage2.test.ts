import { describe, it, expect } from 'vitest';
import { Duplex, PassThrough } from 'node:stream';
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
  createBudgetInterlock,
  createLiveStateGate,
  createThrottleGate,
  createRateLimitGate,
  composeBeforeEgress,
  type Stage2Deps,
  type Stage2Input,
  type JobIdentity,
  type Connectors,
  type ReconstructContext,
  type BudgetLedger,
  type ThrottleController,
  type RateLimiter,
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
    beforeEgress: over.beforeEgress ?? ((): void => {}),
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

  it('the budget interlock surfaces its fixed reason — a denying ledger DENIES with reason budget_exhausted, no socket', async () => {
    const denyingLedger: BudgetLedger = {
      charge: () => Promise.resolve({ ok: false, reason: 'budget_exhausted' }),
    };
    const { deps, connectCount } = makeDeps({
      beforeEgress: createBudgetInterlock({
        ledger: denyingLedger,
        owner: 'broker-A',
        grantJti: 'jti-x',
        specId: 'spec-x',
      }),
    });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'interlock', reason: 'budget_exhausted' });
    expect(connectCount()).toBe(0);
  });

  it('the throttle gate DENIES with its fixed reason (concurrency_exceeded) and opens no socket', async () => {
    const controller: ThrottleController = {
      acquire: () => Promise.resolve({ ok: false, reason: 'concurrency_exceeded' }),
      release: () => Promise.resolve(),
    };
    const { deps, connectCount } = makeDeps({ beforeEgress: createThrottleGate(controller) });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'interlock', reason: 'concurrency_exceeded' });
    expect(connectCount()).toBe(0);
  });

  it('the rate-limit gate DENIES with its fixed reason (rate_limited_host) and opens no socket', async () => {
    const limiter: RateLimiter = {
      take: () => Promise.resolve({ ok: false, reason: 'rate_limited_host' }),
    };
    const { deps, connectCount } = makeDeps({ beforeEgress: createRateLimitGate(limiter) });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'interlock', reason: 'rate_limited_host' });
    expect(connectCount()).toBe(0);
  });

  it('the live-state gate runs BEFORE the budget charge: a closed window DENIES window_closed, no charge, no socket', async () => {
    // A ledger that would succeed — but the gate (composed first) must deny before it is ever consulted.
    let charged = false;
    const ledger: BudgetLedger = {
      charge: () => {
        charged = true;
        return Promise.resolve({
          ok: true,
          receipt: { reservationId: 'r', fenceToken: '1', intentEventId: 'e' },
        });
      },
    };
    const closedGate = createLiveStateGate(() => ({
      nowMs: Date.UTC(2026, 0, 5, 12, 0, 0),
      timezone: 'UTC',
      effectiveFromMs: 0,
      expiresAtMs: Date.UTC(2030, 0, 1),
      revoked: false,
      windows: [], // no allow-window ⇒ window_closed (deny-by-default)
    }));
    const { deps, connectCount } = makeDeps({
      beforeEgress: composeBeforeEgress(
        closedGate,
        createBudgetInterlock({ ledger, owner: 'b', grantJti: 'j', specId: 's' }),
      ),
    });
    const out = await runStage2(await input(), deps);
    expect(out).toMatchObject({ ok: false, stage: 'interlock', reason: 'window_closed' });
    expect(charged).toBe(false); // the gate denied before the charge was attempted
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

  it('interlock denial issues no DNS either — the charge runs strictly before the first egress (SI-055)', async () => {
    let resolveCalls = 0;
    const { deps, connectCount } = makeDeps({
      beforeEgress: () => {
        throw new Error('budget_exhausted');
      },
    });
    const spied: Stage2Deps = {
      ...deps,
      resolve: {
        ...deps.resolve,
        resolve: (h) => {
          resolveCalls++;
          return deps.resolve.resolve(h);
        },
      },
    };
    const out = await runStage2(await input(), spied);
    expect(out).toMatchObject({ ok: false, stage: 'interlock' });
    expect(connectCount()).toBe(0);
    expect(resolveCalls).toBe(0); // no DNS query left the box before the charge
  });

  it('maps a rejecting DNS resolver to a fixed {stage:resolve} instead of escaping', async () => {
    const { deps, connectCount } = makeDeps();
    const rejecting: Stage2Deps = {
      ...deps,
      resolve: { ...deps.resolve, resolve: () => Promise.reject(new Error('ESERVFAIL')) },
    };
    const out = await runStage2(await input(), rejecting);
    expect(out).toMatchObject({ ok: false, stage: 'resolve' });
    expect(connectCount()).toBe(0);
  });

  it('destroys the socket if the send throws after connect (no leaked socket)', async () => {
    let created: Duplex | undefined;
    const mk = (): Duplex => {
      const s = new PassThrough();
      s.write = (() => {
        throw new Error('write_fail');
      }) as typeof s.write;
      created = s;
      return s;
    };
    const { deps } = makeDeps();
    const out = await runStage2(await input(), { ...deps, connectors: { tcp: mk, tls: mk } });
    expect(out).toMatchObject({ ok: false, stage: 'send' });
    expect(created?.destroyed).toBe(true);
  });

  it('consumes the single-use jti exactly once — a replayed grant denies at ingress, no second egress', async () => {
    const { deps, connectCount } = makeDeps(); // one shared consumeJti store across both runs
    const grantToken = await grantFor(makeSpec());
    const first = await runStage2({ identity, grantToken, spec: makeSpec() }, deps);
    expect(first.ok).toBe(true);
    expect(connectCount()).toBe(1);
    const second = await runStage2({ identity, grantToken, spec: makeSpec() }, deps);
    expect(second).toMatchObject({ ok: false, stage: 'ingress', reason: 'replayed' });
    expect(connectCount()).toBe(1); // the replayed grant opens no second socket
  });

  it('a failure {stage, reason} carries only a fixed code — never response bytes', async () => {
    const { deps } = makeDeps({ response: 'GARBAGE-SECRET-TOKEN\r\n\r\n' });
    const out = await runStage2(await input(), deps);
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe('read');
      expect(out.reason).not.toContain('SECRET');
      expect(out.reason).toMatch(/^[a-z_:]+$/);
    }
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

  it('threads the hop and enforces maxHops (follows at the last hop, stops at the budget)', async () => {
    const { deps } = makeDeps({ response: redirectResponse('https://api.example.com/v2') });
    const last = await runStage2(await input({ hop: 4 }), deps); // maxHops 5 ⇒ hop 4 still follows
    expect(last.ok).toBe(true);
    if (last.ok) expect(last.redirect?.follow).toBe(true);

    const { deps: deps2 } = makeDeps({ response: redirectResponse('https://api.example.com/v2') });
    const over = await runStage2(await input({ hop: 5 }), deps2); // hop == maxHops ⇒ depth exceeded
    expect(over.ok).toBe(true);
    if (over.ok && over.redirect && !over.redirect.follow) {
      expect(over.redirect.reason).toBe('redirect_depth_exceeded');
    }
  });
});
