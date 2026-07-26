import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  type RequestSpecContent,
  operatorSessionDigest,
  operatorQueryValueBinding,
  computeQueryValueDigest,
} from '@pentest/spec';
import { reconstructRequest, ReconstructError, type ReconstructContext } from '../src/index.js';

/**
 * Broker request reconstruction (Phase 0 §7.1 step 8 / doc 10 §3 step 3, SI-061). Proves the broker rebuilds the wire
 * request DETERMINISTICALLY from the immutable spec and refuses any deviation BEFORE egress: content-addressed
 * header-set/payload/query fetched by digest; the SECRET query path gated by the version binding + a keyed,
 * constant-time value-digest compare; the operator session gated by its identity digest; every injected value
 * percent-encoded; and the re-canonicalized URL asserted equal to the spec. All I/O is injected — no socket is opened.
 */

const HEX = (c: string): string => c.repeat(64);
const HKEY = new TextEncoder().encode('q'.repeat(32));

function makeSpec(over: Partial<RequestSpecContent> = {}): RequestSpecContent {
  return {
    engagementId: 'eng-1',
    scopeHash: HEX('a'),
    authorizationId: 'auth-1',
    requestClass: 'native',
    kind: 'http',
    checkDigest: null,
    toolTemplateDigest: null,
    headerSetDigest: HEX('h'),
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

function makeCtx(over: Partial<ReconstructContext> = {}): ReconstructContext {
  return {
    fetchHeaderSet: () => Promise.resolve({ headers: [{ name: 'accept', value: '*/*' }] }),
    fetchPayload: () => Promise.resolve(null),
    fetchQueryTemplate: () => Promise.resolve(null),
    resolveSession: () => Promise.resolve(null),
    resolveQueryValues: () => Promise.resolve(null),
    queryValueHmacKey: HKEY,
    ...over,
  };
}

describe('reconstructRequest — happy paths', () => {
  it('reconstructs a minimal GET: injects Host, keeps the fixed header-set, no body/query/session', async () => {
    const req = await reconstructRequest(makeSpec(), makeCtx());
    expect(req).toMatchObject({
      method: 'GET',
      scheme: 'https',
      host: 'example.com',
      port: 443,
      path: '/api',
      query: '',
      targetUrl: 'https://example.com/api',
      body: null,
    });
    // Host is broker-set and first; the curated header-set follows.
    expect(req.headers[0]).toEqual({ name: 'host', value: 'example.com' });
    expect(req.headers).toContainEqual({ name: 'accept', value: '*/*' });
  });

  it('decodes an inert payload to bytes and sets Content-Length', async () => {
    const spec = makeSpec({ method: 'POST', payloadDigest: HEX('p') });
    const ctx = makeCtx({
      fetchPayload: () =>
        Promise.resolve({
          mediaType: 'application/json',
          bodyBase64: Buffer.from('{"x":1}', 'utf8').toString('base64'),
        }),
    });
    const req = await reconstructRequest(spec, ctx);
    expect(req.body).not.toBeNull();
    expect(new TextDecoder().decode(req.body as Uint8Array)).toBe('{"x":1}');
    expect(req.headers).toContainEqual({ name: 'content-length', value: '7' });
  });

  it('builds a CURATED (non-secret) query from a query_template, in canonical key order', async () => {
    const spec = makeSpec({ queryKeysCanonical: 'q&lang', queryTemplateDigest: HEX('t') });
    const ctx = makeCtx({
      fetchQueryTemplate: () =>
        Promise.resolve({
          entries: [
            { key: 'q', value: 'a b' },
            { key: 'lang', value: 'en' },
          ],
        }),
    });
    const req = await reconstructRequest(spec, ctx);
    expect(req.query).toBe('q=a%20b&lang=en');
    expect(req.targetUrl).toBe('https://example.com/api?q=a%20b&lang=en');
  });

  it('builds a SECRET query: verifies the version binding + keyed value digest, then uses the values', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      valueSetName: 'creds',
      valueVersion: 3,
    };
    const entries = [{ key: 'token', value: 's3cr3t' }];
    const spec = makeSpec({
      queryKeysCanonical: 'token',
      queryValueBinding: operatorQueryValueBinding(identity),
      queryValueDigest: computeQueryValueDigest(HKEY, entries),
    });
    const ctx = makeCtx({ resolveQueryValues: () => Promise.resolve({ identity, entries }) });
    const req = await reconstructRequest(spec, ctx);
    expect(req.query).toBe('token=s3cr3t');
  });

  it('reconstructs a WebSocket handshake identically (GET over wss)', async () => {
    const spec = makeSpec({
      kind: 'websocket',
      method: 'GET',
      scheme: 'wss',
      canonicalUrl: 'wss://example.com/socket',
      canonicalPath: '/socket',
      port: 443,
    });
    const req = await reconstructRequest(spec, makeCtx());
    expect(req).toMatchObject({
      scheme: 'wss',
      method: 'GET',
      path: '/socket',
      host: 'example.com',
    });
  });

  it('injects operator-session headers only AFTER the session_digest binding holds', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      accountId: 'acct-9',
      sessionVersion: 2,
    };
    const spec = makeSpec({ sessionDigest: operatorSessionDigest(identity) });
    const ctx = makeCtx({
      resolveSession: () =>
        Promise.resolve({ identity, headers: [{ name: 'cookie', value: 'sid=abc' }] }),
    });
    const req = await reconstructRequest(spec, ctx);
    expect(req.headers).toContainEqual({ name: 'cookie', value: 'sid=abc' });
  });

  it('percent-encodes injected values so they cannot alter request structure', async () => {
    const spec = makeSpec({ queryKeysCanonical: 'q', queryTemplateDigest: HEX('t') });
    const ctx = makeCtx({
      fetchQueryTemplate: () => Promise.resolve({ entries: [{ key: 'q', value: 'a&b=c#d /e' }] }),
    });
    const req = await reconstructRequest(spec, ctx);
    expect(req.query).toBe('q=' + encodeURIComponent('a&b=c#d /e'));
    // the injected value cannot change the path — re-canonicalization still yields the spec's path.
    expect(req.path).toBe('/api');
    expect(req.query).not.toContain('#');
  });

  it('reconstructs against a non-default port from the canonical URL', async () => {
    const spec = makeSpec({
      canonicalUrl: 'https://example.com:8443/api',
      port: 8443,
    });
    const req = await reconstructRequest(spec, makeCtx());
    expect(req.port).toBe(8443);
  });

  it('reconstructs an IP-literal host (re-canonicalization matches on the canonical IP)', async () => {
    const spec = makeSpec({
      canonicalUrl: 'https://93.184.216.34/api',
      canonicalHost: '93.184.216.34',
    });
    const req = await reconstructRequest(spec, makeCtx());
    expect(req).toMatchObject({ host: '93.184.216.34', port: 443, path: '/api' });
  });
});

describe('reconstructRequest — DENY (fail closed) paths', () => {
  it('DENY header_set_not_found', async () => {
    await expect(
      reconstructRequest(makeSpec(), makeCtx({ fetchHeaderSet: () => Promise.resolve(null) })),
    ).rejects.toMatchObject({ reason: 'header_set_not_found' });
  });

  it('DENY header_set_forbidden_header when a curated set smuggles a broker-controlled header', async () => {
    const ctx = makeCtx({
      fetchHeaderSet: () =>
        Promise.resolve({ headers: [{ name: 'Host', value: 'evil.internal' }] }),
    });
    await expect(reconstructRequest(makeSpec(), ctx)).rejects.toMatchObject({
      reason: 'header_set_forbidden_header',
    });
  });

  it('DENY payload_not_found when the referenced inert payload is missing', async () => {
    const spec = makeSpec({ payloadDigest: HEX('p') });
    await expect(
      reconstructRequest(spec, makeCtx({ fetchPayload: () => Promise.resolve(null) })),
    ).rejects.toMatchObject({ reason: 'payload_not_found' });
  });

  it('DENY query_template_not_found for a missing curated template', async () => {
    const spec = makeSpec({ queryKeysCanonical: 'a', queryTemplateDigest: HEX('t') });
    await expect(
      reconstructRequest(spec, makeCtx({ fetchQueryTemplate: () => Promise.resolve(null) })),
    ).rejects.toMatchObject({ reason: 'query_template_not_found' });
  });

  it('DENY query_path_ambiguous when BOTH curated and secret query paths are present', async () => {
    const spec = makeSpec({
      queryKeysCanonical: 'a',
      queryTemplateDigest: HEX('t'),
      queryValueBinding: HEX('b'),
      queryValueDigest: HEX('d'),
    });
    await expect(reconstructRequest(spec, makeCtx())).rejects.toMatchObject({
      reason: 'query_path_ambiguous',
    });
  });

  it('DENY query_path_ambiguous when keys are present but NEITHER query path supplies values', async () => {
    const spec = makeSpec({ queryKeysCanonical: 'a' });
    await expect(reconstructRequest(spec, makeCtx())).rejects.toMatchObject({
      reason: 'query_path_ambiguous',
    });
  });

  it('DENY query_values_unavailable when the secret resolver returns null (fail closed)', async () => {
    const spec = makeSpec({
      queryKeysCanonical: 'a',
      queryValueBinding: HEX('b'),
      queryValueDigest: HEX('d'),
    });
    await expect(
      reconstructRequest(spec, makeCtx({ resolveQueryValues: () => Promise.resolve(null) })),
    ).rejects.toMatchObject({ reason: 'query_values_unavailable' });
  });

  it('DENY query_binding_mismatch when the resolved version differs from the spec binding (rotation)', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      valueSetName: 'creds',
      valueVersion: 3,
    };
    const entries = [{ key: 'token', value: 's3cr3t' }];
    const spec = makeSpec({
      queryKeysCanonical: 'token',
      queryValueBinding: operatorQueryValueBinding({ ...identity, valueVersion: 2 }), // spec bound v2
      queryValueDigest: computeQueryValueDigest(HKEY, entries),
    });
    const ctx = makeCtx({ resolveQueryValues: () => Promise.resolve({ identity, entries }) }); // resolves v3
    await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
      reason: 'query_binding_mismatch',
    });
  });

  it('DENY query_value_mismatch when the resolved values fail the keyed digest (tamper)', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      valueSetName: 'creds',
      valueVersion: 3,
    };
    const spec = makeSpec({
      queryKeysCanonical: 'token',
      queryValueBinding: operatorQueryValueBinding(identity),
      queryValueDigest: computeQueryValueDigest(HKEY, [{ key: 'token', value: 's3cr3t' }]),
    });
    const ctx = makeCtx({
      resolveQueryValues: () =>
        Promise.resolve({ identity, entries: [{ key: 'token', value: 'evil' }] }),
    });
    await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
      reason: 'query_value_mismatch',
    });
  });

  it('DENY query_keys_mismatch when resolved keys differ from the spec canonical keys', async () => {
    const spec = makeSpec({ queryKeysCanonical: 'a&b', queryTemplateDigest: HEX('t') });
    const ctx = makeCtx({
      fetchQueryTemplate: () =>
        Promise.resolve({
          entries: [
            { key: 'a', value: '1' },
            { key: 'X', value: '2' },
          ],
        }),
    });
    await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
      reason: 'query_keys_mismatch',
    });
  });

  it('DENY session_not_found when the lease cannot be resolved', async () => {
    const spec = makeSpec({ sessionDigest: HEX('s') });
    await expect(
      reconstructRequest(spec, makeCtx({ resolveSession: () => Promise.resolve(null) })),
    ).rejects.toMatchObject({ reason: 'session_not_found' });
  });

  it('DENY session_mismatch when the resolved session identity digest != the spec', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      accountId: 'acct-9',
      sessionVersion: 2,
    };
    const spec = makeSpec({
      sessionDigest: operatorSessionDigest({ ...identity, sessionVersion: 1 }),
    });
    const ctx = makeCtx({ resolveSession: () => Promise.resolve({ identity, headers: [] }) });
    await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
      reason: 'session_mismatch',
    });
  });

  it('DENY session_mismatch on a malformed (wrong-length) session digest (defensive)', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      accountId: 'acct-9',
      sessionVersion: 2,
    };
    const spec = makeSpec({ sessionDigest: 'deadbeef' }); // not 64 hex
    const ctx = makeCtx({ resolveSession: () => Promise.resolve({ identity, headers: [] }) });
    await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
      reason: 'session_mismatch',
    });
  });

  it('DENY reconstruction_mismatch when canonical_url disagrees with the spec canonical host', async () => {
    const spec = makeSpec({ canonicalUrl: 'https://elsewhere.test/api' }); // host ≠ canonicalHost
    await expect(reconstructRequest(spec, makeCtx())).rejects.toMatchObject({
      reason: 'reconstruction_mismatch',
    });
  });

  it('DENY reconstruction_mismatch on a malformed canonical_url', async () => {
    const spec = makeSpec({ canonicalUrl: 'not a url' });
    await expect(reconstructRequest(spec, makeCtx())).rejects.toMatchObject({
      reason: 'reconstruction_mismatch',
    });
  });

  it('DENY reconstruction_mismatch when canonical_url scheme / port / path disagree with the spec fields', async () => {
    // Each spec is internally inconsistent (canonical_url vs the separate canonical_* fields) — the re-canonicalize
    // asserts they agree, defending against a spec that slipped through a weaker upstream check.
    const inconsistent: Partial<RequestSpecContent>[] = [
      { canonicalUrl: 'http://example.com:443/api' }, // scheme http ≠ spec https
      { canonicalUrl: 'https://example.com:9999/api' }, // port 9999 ≠ spec 443
      { canonicalUrl: 'https://example.com/OTHER' }, // path /OTHER ≠ spec /api
    ];
    for (const over of inconsistent) {
      await expect(reconstructRequest(makeSpec(over), makeCtx())).rejects.toMatchObject({
        reason: 'reconstruction_mismatch',
      });
    }
  });

  it('error is a ReconstructError whose message is the fixed reason code — never echoing content', async () => {
    const ctx = makeCtx({
      fetchHeaderSet: () =>
        Promise.resolve({ headers: [{ name: 'host', value: 'evil.internal' }] }),
    });
    const err = await reconstructRequest(makeSpec(), ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ReconstructError);
    expect((err as ReconstructError).message).toBe('header_set_forbidden_header');
    expect((err as ReconstructError).message).not.toContain('evil.internal');
  });
});

describe('reconstructRequest — review hardening', () => {
  const sessionIdentity = {
    tenantId: 't1',
    engagementId: 'eng-1',
    accountId: 'acct-9',
    sessionVersion: 2,
  };

  it('DENY when the operator-session lease smuggles a broker-controlled header (Host / Content-Length)', async () => {
    // The session lease is secret-manager data, not the immutable spec — it must be screened just like the curated set,
    // else a lease could override the Host the broker owns (SSRF via Host) or the Content-Length.
    for (const bad of ['host', 'content-length', 'Content-Length']) {
      const spec = makeSpec({ sessionDigest: operatorSessionDigest(sessionIdentity) });
      const ctx = makeCtx({
        resolveSession: () =>
          Promise.resolve({
            identity: sessionIdentity,
            headers: [{ name: bad, value: 'x' }],
          }),
      });
      await expect(reconstructRequest(spec, ctx)).rejects.toMatchObject({
        reason: 'header_set_forbidden_header',
      });
    }
  });

  it('DENY a curated header-set that smuggles Content-Length (not only Host)', async () => {
    const ctx = makeCtx({
      fetchHeaderSet: () => Promise.resolve({ headers: [{ name: 'content-length', value: '0' }] }),
    });
    await expect(reconstructRequest(makeSpec(), ctx)).rejects.toMatchObject({
      reason: 'header_set_forbidden_header',
    });
  });

  it('DENY a header name that evades the filter by trailing whitespace or is otherwise malformed', async () => {
    for (const bad of ['host ', ' host', 'ho st', 'content-length\t', 'bad:name', 'x\r']) {
      const ctx = makeCtx({
        fetchHeaderSet: () => Promise.resolve({ headers: [{ name: bad, value: 'v' }] }),
      });
      await expect(reconstructRequest(makeSpec(), ctx), bad).rejects.toMatchObject({
        reason: 'header_set_forbidden_header',
      });
    }
  });

  it('sets a Host header with the non-default port, and brackets an IPv6 literal', async () => {
    const withPort = await reconstructRequest(
      makeSpec({ canonicalUrl: 'https://example.com:8443/api', port: 8443 }),
      makeCtx(),
    );
    expect(withPort.headers[0]).toEqual({ name: 'host', value: 'example.com:8443' });

    const v6 = await reconstructRequest(
      makeSpec({
        canonicalUrl: 'https://[2606:2800:220:1::1]/api',
        canonicalHost: '2606:2800:220:1::1',
      }),
      makeCtx(),
    );
    expect(v6.headers[0]).toEqual({ name: 'host', value: '[2606:2800:220:1::1]' });
  });

  it('DENY query_path_ambiguous when a query path digest/binding is present but canonical keys are null', async () => {
    // Fail closed: such a spec would otherwise silently drop the query AND skip the secret binding/HMAC verification.
    const curated = makeSpec({ queryKeysCanonical: null, queryTemplateDigest: HEX('t') });
    await expect(reconstructRequest(curated, makeCtx())).rejects.toMatchObject({
      reason: 'query_path_ambiguous',
    });
    const secret = makeSpec({
      queryKeysCanonical: null,
      queryValueBinding: HEX('b'),
      queryValueDigest: HEX('d'),
    });
    await expect(reconstructRequest(secret, makeCtx())).rejects.toMatchObject({
      reason: 'query_path_ambiguous',
    });
  });

  it('Content-Length is the BYTE length of a multibyte body, not the character count', async () => {
    const text = '{"x":"€"}'; // the euro sign is 3 UTF-8 bytes ⇒ 11 octets, but 9 code units
    const spec = makeSpec({ method: 'POST', payloadDigest: HEX('p') });
    const ctx = makeCtx({
      fetchPayload: () =>
        Promise.resolve({
          mediaType: 'application/json',
          bodyBase64: Buffer.from(text, 'utf8').toString('base64'),
        }),
    });
    const req = await reconstructRequest(spec, ctx);
    expect(req.headers).toContainEqual({ name: 'content-length', value: '11' });
    expect(text.length).toBe(9); // guards the intent: 9 chars, 11 bytes
  });

  it('pins duplicate-key and the trailing-empty-segment behaviour of canonical keys', async () => {
    // Duplicate keys are preserved in order (the value set must supply matching keys in the same order)…
    const dup = makeSpec({ queryKeysCanonical: 'a&a', queryTemplateDigest: HEX('t') });
    const dupReq = await reconstructRequest(
      dup,
      makeCtx({
        fetchQueryTemplate: () =>
          Promise.resolve({
            entries: [
              { key: 'a', value: '1' },
              { key: 'a', value: '2' },
            ],
          }),
      }),
    );
    expect(dupReq.query).toBe('a=1&a=2');
    // …and a mismatch against the declared keys still fails closed.
    const bad = makeSpec({ queryKeysCanonical: 'a&', queryTemplateDigest: HEX('t') });
    await expect(
      reconstructRequest(
        bad,
        makeCtx({
          fetchQueryTemplate: () => Promise.resolve({ entries: [{ key: 'a', value: '1' }] }),
        }),
      ),
    ).rejects.toMatchObject({ reason: 'query_keys_mismatch' });
  });

  it('secret-path DENY errors are fixed reason codes that never echo the secret / identity / digest', async () => {
    const identity = {
      tenantId: 't1',
      engagementId: 'eng-1',
      valueSetName: 'creds',
      valueVersion: 3,
    };
    const good = [{ key: 'token', value: 's3cr3t' }];
    const specBase = {
      queryKeysCanonical: 'token',
      queryValueBinding: operatorQueryValueBinding(identity),
      queryValueDigest: computeQueryValueDigest(HKEY, good),
    };

    // value tamper → query_value_mismatch, message carries neither the tampered value nor the digest.
    const valErr = await reconstructRequest(
      makeSpec(specBase),
      makeCtx({
        resolveQueryValues: () =>
          Promise.resolve({ identity, entries: [{ key: 'token', value: 'evil-secret' }] }),
      }),
    ).catch((e: unknown) => e);
    expect((valErr as ReconstructError).message).toBe('query_value_mismatch');
    expect((valErr as ReconstructError).message).not.toContain('evil-secret');
    expect((valErr as ReconstructError).message).not.toContain(specBase.queryValueDigest);

    // wrong version → query_binding_mismatch, message carries neither the binding nor the value-set name.
    const bindErr = await reconstructRequest(
      makeSpec({
        ...specBase,
        queryValueBinding: operatorQueryValueBinding({ ...identity, valueVersion: 9 }),
      }),
      makeCtx({ resolveQueryValues: () => Promise.resolve({ identity, entries: good }) }),
    ).catch((e: unknown) => e);
    expect((bindErr as ReconstructError).message).toBe('query_binding_mismatch');
    expect((bindErr as ReconstructError).message).not.toContain('creds');

    // wrong session → session_mismatch, message carries neither the account nor the digest.
    const sessErr = await reconstructRequest(
      makeSpec({ sessionDigest: operatorSessionDigest({ ...sessionIdentity, sessionVersion: 1 }) }),
      makeCtx({
        resolveSession: () => Promise.resolve({ identity: sessionIdentity, headers: [] }),
      }),
    ).catch((e: unknown) => e);
    expect((sessErr as ReconstructError).message).toBe('session_mismatch');
    expect((sessErr as ReconstructError).message).not.toContain('acct-9');
  });
});
