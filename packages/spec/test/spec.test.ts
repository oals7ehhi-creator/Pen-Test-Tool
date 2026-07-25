import { describe, it, expect } from 'vitest';
import {
  computeSpecSha256,
  canonicalSpecJson,
  specDigestObject,
  SPEC_DIGEST_FIELDS,
  type RequestSpecContent,
} from '../src/index.js';

/**
 * request_spec content-addressing (Phase 0 §7.0). Proves the digest covers EXACTLY the request-determining fields,
 * that every content field changes it, and — the security-critical property — that instance identity, secret
 * pointers, and the advisory mode are NOT part of the identity (they aren't even in `RequestSpecContent`, and the
 * covered field set is asserted here so a future edit can't silently fold one in).
 */

const base: RequestSpecContent = {
  engagementId: 'eng-1',
  scopeHash: 'a'.repeat(64),
  authorizationId: 'auth-1',
  requestClass: 'native',
  kind: 'http',
  checkDigest: 'c'.repeat(64),
  toolTemplateDigest: null,
  headerSetDigest: 'h'.repeat(64),
  payloadDigest: null,
  wsFrameSetDigest: null,
  method: 'GET',
  canonicalUrl: 'https://example.com/api/v1',
  canonicalHost: 'example.com',
  port: 443,
  scheme: 'https',
  canonicalPath: '/api/v1',
  queryKeysCanonical: 'a,b,c',
  queryTemplateDigest: null,
  queryValueBinding: null,
  queryValueDigest: null,
  sessionDigest: null,
  approvalRequired: false,
};

describe('spec_sha256 field membership (§7.0)', () => {
  it('covers exactly the 22 request-determining fields', () => {
    expect(SPEC_DIGEST_FIELDS).toHaveLength(22);
    expect([...SPEC_DIGEST_FIELDS].sort()).toEqual(Object.keys(specDigestObject(base)).sort());
  });

  it('EXCLUDES instance identity, secret pointers, and the advisory mode', () => {
    const excluded = [
      'run_id',
      'job_id',
      'approval_ref',
      'session_ref',
      'query_value_ref',
      'mode',
      'tenant_id',
    ];
    for (const f of excluded) expect(SPEC_DIGEST_FIELDS).not.toContain(f);
    const json = canonicalSpecJson(base);
    for (const f of excluded) expect(json).not.toContain(`"${f}"`);
  });

  it('the covered set names the non-secret bindings that DO bind identity', () => {
    for (const f of ['query_value_binding', 'session_digest', 'scope_hash', 'authorization_id']) {
      expect(SPEC_DIGEST_FIELDS).toContain(f);
    }
  });
});

describe('computeSpecSha256', () => {
  it('is a stable 64-hex digest', () => {
    expect(computeSpecSha256(base)).toMatch(/^[0-9a-f]{64}$/);
    expect(computeSpecSha256(base)).toBe(computeSpecSha256({ ...base }));
  });

  it('changes when ANY request-determining field changes', () => {
    const d0 = computeSpecSha256(base);
    const mutations: Partial<RequestSpecContent>[] = [
      { engagementId: 'eng-2' },
      { scopeHash: 'b'.repeat(64) },
      { authorizationId: 'auth-2' },
      { requestClass: 'tool_driven' },
      { kind: 'websocket' },
      { checkDigest: 'd'.repeat(64) },
      { toolTemplateDigest: 't'.repeat(64) },
      { headerSetDigest: 'g'.repeat(64) },
      { payloadDigest: 'p'.repeat(64) },
      { wsFrameSetDigest: 'w'.repeat(64) },
      { method: 'POST' },
      { canonicalUrl: 'https://example.com/api/v2' },
      { canonicalHost: 'evil.example' },
      { port: 8443 },
      { scheme: 'http' },
      { canonicalPath: '/api/v2' },
      { queryKeysCanonical: 'a,b' },
      { queryTemplateDigest: 'q'.repeat(64) },
      { queryValueBinding: 'v'.repeat(64) },
      { queryValueDigest: 'k'.repeat(64) },
      { sessionDigest: 's'.repeat(64) },
      { approvalRequired: true },
    ];
    const digests = new Set<string>([d0]);
    for (const m of mutations) {
      const d = computeSpecSha256({ ...base, ...m });
      expect(d, `mutation ${JSON.stringify(m)} did not change the digest`).not.toBe(d0);
      digests.add(d);
    }
    // Every mutation produced a distinct digest (no collisions across the 22 fields).
    expect(digests.size).toBe(mutations.length + 1);
  });

  it('a null optional and a present value produce different digests', () => {
    const withNull = computeSpecSha256({ ...base, payloadDigest: null });
    const withValue = computeSpecSha256({ ...base, payloadDigest: 'p'.repeat(64) });
    expect(withNull).not.toBe(withValue);
  });

  it('canonicalSpecJson has sorted keys and only snake_case digest fields', () => {
    const json = canonicalSpecJson(base);
    expect(json.startsWith('{"approval_required":')).toBe(true); // sorted: approval_required is first
    const keys = [...json.matchAll(/"([a-z_]+)":/g)].map((m) => m[1]);
    // top-level keys only (values here contain no nested objects)
    expect(new Set(keys)).toEqual(new Set(SPEC_DIGEST_FIELDS));
  });
});
