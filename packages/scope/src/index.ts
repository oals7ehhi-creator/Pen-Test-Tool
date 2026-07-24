/**
 * @pentest/scope — the Scope Authority's pure decision core (Phase 2, slice 1).
 *
 * This slice implements the SSRF / network-policy chokepoint (Phase 0 §5 canonicalization + §6 two-tier network
 * guard): every candidate address is decoded to canonical bytes and classified hard_deny / restricted / permitted,
 * and full candidate URLs are canonicalized (scheme/host/port/path, userinfo stripped). Full allow/exclude scope-
 * entry matching, the immutable request_spec + two-stage JIT-grant flow, and the Guarded Egress Broker arrive in
 * later Phase 2 slices.
 */
export {
  type NetworkTier,
  type GuardVerdict,
  type ParsedIp,
  parseStrictDottedQuad,
  parseIpv4Loose,
  parseIpv6,
  parseIpLiteral,
  inCidrV4,
  inCidrV6,
  classifyBytes,
  guardIp,
} from './ip.js';

export {
  SCHEMES,
  type Scheme,
  type CanonicalHost,
  type CanonicalUrl,
  type UrlParseResult,
  canonicalizeScheme,
  canonicalizePort,
  canonicalizeHost,
  canonicalizePath,
  canonicalizeUrl,
  guardUrl,
} from './canonicalize.js';
