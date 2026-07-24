import { describe, it, expect } from 'vitest';
import {
  evaluateScope,
  evaluateUrl,
  candidateFromUrl,
  type ScopeVersion,
  type ScopeEntry,
  type Candidate,
} from '../src/index.js';

/**
 * Scope-entry matching + deny-by-default decision battery (Phase 0 §4 + §7.1 steps 1–5). This is the pure Scope
 * Authority decision: canonical candidate × frozen scope_version → ALLOW / DENY, in the spec's precedence —
 * scheme → IP-literal network guard (Tier A absolute) → exclusions-first → allowlist → port + host-bound path,
 * deny-by-default throughout. The Broker preconditions (engagement/authorization/window/budget/approval) are a
 * later slice and deliberately NOT exercised here.
 */

const scope = (...entries: ScopeEntry[]): ScopeVersion => ({ entries });

/** Build a candidate, asserting the URL canonicalizes (helper for the non-SSRF cases). */
function cand(rawUrl: string, method = 'GET'): Candidate {
  const built = candidateFromUrl(rawUrl, method);
  if (!built.ok) throw new Error(`fixture URL did not canonicalize: ${rawUrl} (${built.reason})`);
  return built.candidate;
}

describe('deny-by-default (no scope, no request)', () => {
  it('an empty scope denies every candidate', () => {
    const empty = scope();
    expect(evaluateUrl('https://example.com/', empty).allow).toBe(false);
    expect(evaluateUrl('https://anything.test/path', empty).allow).toBe(false);
    const d = evaluateScope(cand('https://example.com/'), empty);
    expect(d).toMatchObject({ allow: false, reason: 'no_host_match' });
  });

  it('a host not named by any allow entry is denied', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'allowed.example',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://other.example/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });
});

describe('domain matching (§4.3, §4.4)', () => {
  it('exact apex match (no wildcard, no subtree)', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://www.example.com/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });

  it('wildcard matches subdomains but NOT the apex', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: true,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://api.example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://a.b.example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });

  it('wildcard + includeSubdomains matches the apex too', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: true,
      includeSubdomains: true,
    });
    expect(evaluateUrl('https://example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://api.example.com/', s).allow).toBe(true);
  });

  it('includeSubdomains on a non-wildcard entry matches apex + subtree', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: true,
    });
    expect(evaluateUrl('https://example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://deep.sub.example.com/', s).allow).toBe(true);
  });

  it('a suffix that is not a label boundary does not match (no example.com vs notexample.com confusion)', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: true,
      includeSubdomains: true,
    });
    expect(evaluateUrl('https://notexample.com/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
    expect(evaluateUrl('https://evilexample.com/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });

  it('matches after host canonicalization (case, trailing dot, IDNA)', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://EXAMPLE.com./', s).allow).toBe(true);
    const idn = scope({
      class: 'domain',
      hostAscii: 'xn--bcher-kva.example',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://bücher.example/', idn).allow).toBe(true);
  });
});

describe('exclusions always win (§4.5)', () => {
  it('an excluded subdomain is denied even under an allowed wildcard', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: true, includeSubdomains: true },
      {
        class: 'domain',
        hostAscii: 'secret.example.com',
        wildcard: false,
        includeSubdomains: false,
        isExclusion: true,
      },
    );
    expect(evaluateUrl('https://api.example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://secret.example.com/', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
  });

  it('an exclusion wins over the exact apex it would otherwise allow', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'domain',
        hostAscii: 'example.com',
        wildcard: false,
        includeSubdomains: false,
        isExclusion: true,
      },
    );
    expect(evaluateUrl('https://example.com/', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
  });

  it('a path_prefix exclusion removes a subtree from an allowed host', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        pathPrefix: '/admin',
        isExclusion: true,
      },
    );
    expect(evaluateUrl('https://example.com/public', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/admin', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
    expect(evaluateUrl('https://example.com/admin/users', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
    // segment boundary: /administrator is NOT under /admin
    expect(evaluateUrl('https://example.com/administrator', s).allow).toBe(true);
  });

  it('an api_resource exclusion removes a specific operation from an allowed host', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'api_resource',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        operations: ['DELETE /v1/users'],
        isExclusion: true,
      },
    );
    // GET is fine (host has no bound-path ALLOW entries → unconstrained on path); the excluded op is denied.
    expect(evaluateUrl('https://example.com/v1/users', s, 'GET').allow).toBe(true);
    expect(evaluateUrl('https://example.com/v1/users', s, 'DELETE')).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
  });

  it('a port exclusion removes a port from an otherwise allowed host', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      { class: 'port', low: 443, high: 443 },
      { class: 'port', low: 8443, high: 8443 },
      { class: 'port', low: 8443, high: 8443, isExclusion: true },
    );
    expect(evaluateUrl('https://example.com/', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com:8443/', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
  });
});

describe('IP + CIDR matching', () => {
  it('exact IP literal match', () => {
    const s = scope({ class: 'ip', ip: '203.0.113.5' });
    // 203.0.113.0/24 is TEST-NET-3 documentation → Tier A hard-deny before allow matching even runs.
    expect(evaluateUrl('https://203.0.113.5/', s).allow).toBe(false);
  });

  it('a public IP literal in scope is allowed on its default port', () => {
    const s = scope({ class: 'ip', ip: '93.184.216.34' });
    expect(evaluateUrl('https://93.184.216.34/', s).allow).toBe(true);
    expect(evaluateUrl('https://93.184.216.35/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });

  it('a public CIDR contains its members', () => {
    const s = scope({ class: 'cidr', version: 4, base: '93.184.216.0', prefix: 24 });
    expect(evaluateUrl('https://93.184.216.1/', s).allow).toBe(true);
    expect(evaluateUrl('https://93.184.216.254/', s).allow).toBe(true);
    expect(evaluateUrl('https://93.184.217.1/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });

  it('an IPv6 CIDR contains its members', () => {
    const s = scope({ class: 'cidr', version: 6, base: '2606:2800:220::', prefix: 48 });
    expect(evaluateUrl('https://[2606:2800:220::1]/', s).allow).toBe(true);
    expect(evaluateUrl('https://[2606:2800:221::1]/', s)).toMatchObject({
      allow: false,
      reason: 'no_host_match',
    });
  });
});

describe('network guard is not overridable by allowlisting (§0.4, §6)', () => {
  // Each scope deliberately allows http AND names the Tier A address as an elevated allow entry — proving the
  // guard denies even when the scheme passes and the operator tried to allowlist the address under elevation.
  const httpAllowed: ScopeEntry = { class: 'protocol', scheme: 'http' };

  it('a Tier A literal is hard-denied even when explicitly allowlisted', () => {
    const s = scope(httpAllowed, { class: 'ip', ip: '127.0.0.1', elevated: true });
    const d = evaluateScope(cand('http://127.0.0.1/'), s, { elevationGranted: true });
    expect(d.allow).toBe(false);
    expect(d.reason).toBe('network_guard:loopback');
  });

  it('cloud metadata is hard-denied even inside an allowed CIDR and with elevation granted', () => {
    const s = scope(httpAllowed, {
      class: 'cidr',
      version: 4,
      base: '169.254.0.0',
      prefix: 16,
      elevated: true,
    });
    const d = evaluateScope(cand('http://169.254.169.254/latest/meta-data/'), s, {
      elevationGranted: true,
    });
    expect(d).toMatchObject({ allow: false, reason: 'network_guard:cloud_metadata' });
  });

  it('an obfuscated Tier A literal is hard-denied (decimal / hex / mapped-v6)', () => {
    const s = scope(httpAllowed, { class: 'ip', ip: '127.0.0.1', elevated: true });
    for (const u of ['http://2130706433/', 'http://0x7f000001/', 'http://[::ffff:127.0.0.1]/']) {
      expect(evaluateUrl(u, s, 'GET', { elevationGranted: true })).toMatchObject({ allow: false });
      expect(evaluateUrl(u, s, 'GET', { elevationGranted: true }).reason).toMatch(
        /^network_guard:/,
      );
    }
  });
});

describe('Tier B elevation gating (§0.4, §4.6)', () => {
  const restrictedIp = 'https://10.0.0.5/';

  it('a Tier B host with NO elevated entry is denied even if the range is allowlisted', () => {
    const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 16 });
    expect(evaluateUrl(restrictedIp, s)).toMatchObject({
      allow: false,
      reason: 'restricted_range_not_elevated',
    });
  });

  it('a Tier B host WITH an elevated entry but NO elevation context is denied', () => {
    const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 16, elevated: true });
    expect(evaluateUrl(restrictedIp, s)).toMatchObject({
      allow: false,
      reason: 'restricted_range_elevation_not_granted',
    });
  });

  it('a Tier B host WITH an elevated entry AND elevation granted is allowed', () => {
    const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 16, elevated: true });
    expect(evaluateUrl(restrictedIp, s, 'GET', { elevationGranted: true })).toMatchObject({
      allow: true,
      reason: 'in_scope',
    });
  });

  it('elevation on a DIFFERENT (non-matching) entry does not elevate the candidate', () => {
    const s = scope(
      { class: 'cidr', version: 4, base: '192.168.0.0', prefix: 16, elevated: true },
      { class: 'cidr', version: 4, base: '10.0.0.0', prefix: 16 },
    );
    expect(evaluateUrl(restrictedIp, s, 'GET', { elevationGranted: true })).toMatchObject({
      allow: false,
      reason: 'restricted_range_not_elevated',
    });
  });

  it('an ULA IPv6 (Tier B) is gated the same way', () => {
    const s = scope({ class: 'cidr', version: 6, base: 'fd00::', prefix: 8, elevated: true });
    expect(evaluateUrl('https://[fd00::1]/', s)).toMatchObject({
      allow: false,
      reason: 'restricted_range_elevation_not_granted',
    });
    expect(evaluateUrl('https://[fd00::1]/', s, 'GET', { elevationGranted: true }).allow).toBe(
      true,
    );
  });
});

describe('scheme (§4.3, §5.4)', () => {
  const host: ScopeEntry = {
    class: 'domain',
    hostAscii: 'example.com',
    wildcard: false,
    includeSubdomains: false,
  };

  it('https is default-allowed with no protocol entry', () => {
    expect(evaluateUrl('https://example.com/', scope(host)).allow).toBe(true);
  });

  it('http is denied unless an explicit protocol entry allows it', () => {
    expect(evaluateUrl('http://example.com/', scope(host))).toMatchObject({
      allow: false,
      reason: 'scheme_not_allowed',
    });
    const withHttp = scope(host, { class: 'protocol', scheme: 'http' });
    expect(evaluateUrl('http://example.com/', withHttp).allow).toBe(true);
    // https still allowed alongside the added http entry
    expect(evaluateUrl('https://example.com/', withHttp).allow).toBe(true);
  });

  it('a protocol exclusion removes a scheme (wss) from scope', () => {
    const s = scope(
      host,
      { class: 'protocol', scheme: 'wss' },
      { class: 'protocol', scheme: 'wss', isExclusion: true },
    );
    expect(evaluateUrl('wss://example.com/', s)).toMatchObject({
      allow: false,
      reason: 'excluded',
    });
  });

  it('an unsupported scheme never canonicalizes (fails closed at the URL layer)', () => {
    expect(evaluateUrl('file:///etc/passwd', scope(host)).allow).toBe(false);
    expect(evaluateUrl('gopher://example.com/', scope(host)).reason).toMatch(/^uncanonicalizable:/);
  });
});

describe('port (§4.3, §5.3)', () => {
  const host: ScopeEntry = {
    class: 'domain',
    hostAscii: 'example.com',
    wildcard: false,
    includeSubdomains: false,
  };

  it('with no port entry, only the scheme-default port is allowed', () => {
    expect(evaluateUrl('https://example.com/', scope(host)).allow).toBe(true); // 443 default
    expect(evaluateUrl('https://example.com:8443/', scope(host))).toMatchObject({
      allow: false,
      reason: 'port_not_allowed',
    });
  });

  it('an explicit :443 equals the default (no bypass by re-stating the default)', () => {
    expect(evaluateUrl('https://example.com:443/', scope(host)).allow).toBe(true);
  });

  it('an explicit port entry defines the allowed set (default is NOT implicitly allowed)', () => {
    const s = scope(host, { class: 'port', low: 8443, high: 8443 });
    expect(evaluateUrl('https://example.com:8443/', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/', s)).toMatchObject({
      allow: false,
      reason: 'port_not_allowed',
    });
  });

  it('a port range allows its members inclusively', () => {
    const s = scope(host, { class: 'port', low: 8000, high: 8100 });
    expect(evaluateUrl('https://example.com:8000/', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com:8100/', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com:8101/', s)).toMatchObject({
      allow: false,
      reason: 'port_not_allowed',
    });
  });
});

describe('host-bound path & api_resource (§4.2 blocker-5, §4.3)', () => {
  it('a path_prefix constrains an allowed host to a subtree (segment boundary)', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        pathPrefix: '/api',
      },
    );
    expect(evaluateUrl('https://example.com/api', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/api/v1/users', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/apiv2', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
    expect(evaluateUrl('https://example.com/other', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
  });

  it('encoded traversal cannot escape a bound path prefix (canonicalized before match)', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        pathPrefix: '/api',
      },
    );
    // /api/%2e%2e/admin → /admin → outside the /api subtree → denied
    expect(evaluateUrl('https://example.com/api/%2e%2e/admin', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
  });

  it('a host with no path entries is unconstrained on path', () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(evaluateUrl('https://example.com/anything/at/all', s).allow).toBe(true);
  });

  it('a path bound to a DIFFERENT host does not constrain this host', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      { class: 'domain', hostAscii: 'other.com', wildcard: false, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'other.com',
        boundHostWildcard: false,
        pathPrefix: '/api',
      },
    );
    // example.com has no bound-path entries → unconstrained; other.com IS constrained.
    expect(evaluateUrl('https://example.com/anything', s).allow).toBe(true);
    expect(evaluateUrl('https://other.com/anything', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
    expect(evaluateUrl('https://other.com/api/x', s).allow).toBe(true);
  });

  it('api_resource matches only the listed (METHOD, path) operations', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'api_resource',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        operations: ['GET /v1/users', 'POST /v1/users'],
      },
    );
    expect(evaluateUrl('https://example.com/v1/users', s, 'GET').allow).toBe(true);
    expect(evaluateUrl('https://example.com/v1/users', s, 'POST').allow).toBe(true);
    // method not listed
    expect(evaluateUrl('https://example.com/v1/users', s, 'DELETE')).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
    // path not listed
    expect(evaluateUrl('https://example.com/v1/admin', s, 'GET')).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
    // method is case-normalized by candidateFromUrl
    expect(evaluateUrl('https://example.com/v1/users', s, 'get').allow).toBe(true);
  });

  it('a wildcard-bound path applies across the subtree', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: true, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: true,
        pathPrefix: '/api',
      },
    );
    expect(evaluateUrl('https://a.example.com/api/x', s).allow).toBe(true);
    expect(evaluateUrl('https://a.example.com/nope', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
  });

  it('when a host has multiple bound-path entries, matching ANY one allows the path', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        pathPrefix: '/api',
      },
      {
        class: 'path_prefix',
        boundHostAscii: 'example.com',
        boundHostWildcard: false,
        pathPrefix: '/health',
      },
    );
    expect(evaluateUrl('https://example.com/api/x', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/health', s).allow).toBe(true);
    expect(evaluateUrl('https://example.com/metrics', s)).toMatchObject({
      allow: false,
      reason: 'path_not_allowed',
    });
  });
});

describe('SSRF through a candidate URL is denied regardless of scope (§6)', () => {
  const wideOpen = scope(
    { class: 'domain', hostAscii: 'example.com', wildcard: true, includeSubdomains: true },
    { class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8, elevated: true },
    { class: 'protocol', scheme: 'http' },
  );
  const ssrf = [
    'http://127.0.0.1/',
    'http://0x7f000001/',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'https://[::1]/',
    'http://169.254.169.254/latest/meta-data/',
    'http://[::ffff:169.254.169.254]/',
    'http://255.255.255.255/',
  ];
  for (const u of ssrf) {
    it(`denies ${u}`, () => {
      const d = evaluateUrl(u, wideOpen, 'GET', { elevationGranted: true });
      expect(d.allow).toBe(false);
      expect(d.reason).toMatch(/^network_guard:/);
    });
  }

  it('userinfo cannot smuggle a metadata host past the guard', () => {
    const d = evaluateUrl('https://trusted.example@169.254.169.254/', wideOpen, 'GET', {
      elevationGranted: true,
    });
    expect(d).toMatchObject({ allow: false, reason: 'network_guard:cloud_metadata' });
  });
});

describe('candidateFromUrl', () => {
  it('returns a canonical candidate for a well-formed URL and normalizes the method', () => {
    const built = candidateFromUrl('HTTPS://Example.COM/api/../v1', 'post');
    expect(built.ok).toBe(true);
    if (built.ok) {
      expect(built.candidate.scheme).toBe('https');
      expect(built.candidate.host).toMatchObject({ kind: 'domain', hostAscii: 'example.com' });
      expect(built.candidate.port).toBe(443);
      expect(built.candidate.path).toBe('/v1');
      expect(built.candidate.method).toBe('POST');
    }
  });

  it('returns a reason for a URL that does not canonicalize', () => {
    const built = candidateFromUrl('not a url');
    expect(built.ok).toBe(false);
    if (!built.ok) expect(built.reason).toBe('malformed_url');
  });
});
