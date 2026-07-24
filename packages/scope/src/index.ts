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

export {
  type EntryClass,
  type DomainEntry,
  type IpEntry,
  type CidrEntry,
  type PortEntry,
  type ProtocolEntry,
  type PathPrefixEntry,
  type ApiResourceEntry,
  type ScopeEntry,
  type ScopeVersion,
  DEFAULT_ALLOWED_SCHEME,
} from './model.js';

export {
  type Candidate,
  type EvalContext,
  type ScopeDecision,
  candidateFromUrl,
  evaluateScope,
  evaluateUrl,
} from './evaluate.js';

export {
  type ScopeBreadth,
  type BreadthCeilings,
  type BreadthViolation,
  type BreadthReport,
  ABSOLUTE_MIN_IPV4_PREFIX,
  ABSOLUTE_MIN_IPV6_PREFIX,
  computeScopeBreadth,
  evaluateBreadth,
} from './breadth.js';
