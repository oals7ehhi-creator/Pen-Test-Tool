/**
 * The deny-by-default scope decision (Phase 0 §4 + §7.1 steps 1–5). Given a canonical candidate and a frozen
 * `ScopeVersion`, decide ALLOW / DENY in the spec's precedence:
 *
 *   1. scheme allowed?          (https is default-allowed; http/ws/wss need an explicit `protocol` entry)
 *   2. IP-literal network guard (Tier A is an absolute hard-deny — §6)
 *   3. exclusions FIRST         (any matching exclusion denies, even over an allow — §4.5)
 *   4. allowlist                (host must match; Tier B requires a matching `elevated` entry + elevation context)
 *   5. port + host-bound path   (deny-by-default: no matching allow ⇒ DENY)
 *
 * No scope, no request: an empty scope denies everything. This is the pure decision; the two-stage flow's
 * preconditions (engagement/authorization/window/budget/approval) and grant minting are the Broker layer (slice 4).
 */

import { classifyBytes, inCidrV4, inCidrV6, parseIpLiteral, type ParsedIp } from './ip.js';
import { canonicalizeUrl, type CanonicalHost, type Scheme } from './canonicalize.js';
import {
  DEFAULT_ALLOWED_SCHEME,
  type ScopeEntry,
  type ScopeVersion,
  type DomainEntry,
  type IpEntry,
  type CidrEntry,
  type PathPrefixEntry,
  type ApiResourceEntry,
} from './model.js';

/** Host-dimension entry classes (domain / ip / cidr). */
type HostEntry = DomainEntry | IpEntry | CidrEntry;
const isHostEntry = (e: ScopeEntry): e is HostEntry =>
  e.class === 'domain' || e.class === 'ip' || e.class === 'cidr';

/** Host-bound path entry classes (path_prefix / api_resource). */
type BoundPathEntry = PathPrefixEntry | ApiResourceEntry;
const isBoundPathEntry = (e: ScopeEntry): e is BoundPathEntry =>
  e.class === 'path_prefix' || e.class === 'api_resource';

const SCHEME_DEFAULT_PORT: Record<Scheme, number> = { https: 443, http: 80, wss: 443, ws: 80 };

export interface Candidate {
  readonly scheme: Scheme;
  readonly host: CanonicalHost;
  readonly port: number;
  readonly path: string;
  /** HTTP method (for `api_resource` matching); defaults to GET. */
  readonly method: string;
}

export interface EvalContext {
  /**
   * True when the full Tier B elevation precondition holds for this engagement (a dual-approved
   * restricted-range approval AND authorization.internal_testing_granted). The pure evaluator takes this as
   * context; the Scope Authority resolves it. Absent ⇒ Tier B is denied exactly like Tier A.
   */
  readonly elevationGranted?: boolean;
}

export type ScopeDecision =
  | { readonly allow: true; readonly reason: string }
  | { readonly allow: false; readonly reason: string };

const ALLOW = (reason: string): ScopeDecision => ({ allow: true, reason });
const DENY = (reason: string): ScopeDecision => ({ allow: false, reason });

/** Build a candidate from a raw URL + method, or return a DENY reason if it does not canonicalize. */
export function candidateFromUrl(
  rawUrl: string,
  method = 'GET',
):
  | { readonly ok: true; readonly candidate: Candidate }
  | { readonly ok: false; readonly reason: string } {
  const parsed = canonicalizeUrl(rawUrl);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const { scheme, host, port, path } = parsed.url;
  return { ok: true, candidate: { scheme, host, port, path, method: method.toUpperCase() } };
}

// --- host matching -------------------------------------------------------------------------------------------

/** Match a candidate domain host against a (possibly wildcard / subtree) host pattern (§4.3, §4.4). */
function domainMatches(
  hostAscii: string,
  patternHost: string,
  wildcard: boolean,
  includeSubdomains: boolean,
): boolean {
  const isSubdomain =
    hostAscii.endsWith('.' + patternHost) && hostAscii.length > patternHost.length + 1;
  const isApex = hostAscii === patternHost;
  if (wildcard) return isSubdomain || (isApex && includeSubdomains);
  return isApex || (includeSubdomains && isSubdomain);
}

function ipMatchesLiteral(candidate: ParsedIp, literal: string): boolean {
  const e = parseIpLiteral(literal);
  if (e === null || e.version !== candidate.version) return false;
  if (e.bytes.length !== candidate.bytes.length) return false;
  return e.bytes.every((b, i) => b === candidate.bytes[i]);
}

function ipMatchesCidr(candidate: ParsedIp, version: 4 | 6, base: string, prefix: number): boolean {
  if (candidate.version !== version) return false;
  if (version === 4) return inCidrV4(candidate.bytes, base, prefix);
  const baseBytes = parseIpLiteral(base);
  if (baseBytes === null || baseBytes.version !== 6) return false;
  return inCidrV6(candidate.bytes, baseBytes.bytes, prefix);
}

/** Does a host-dimension entry match the candidate host? (domain entries vs domain hosts, ip/cidr vs ip.) */
function hostEntryMatches(host: CanonicalHost, e: HostEntry): boolean {
  if (e.class === 'domain')
    return (
      host.kind === 'domain' &&
      domainMatches(host.hostAscii, e.hostAscii, e.wildcard, e.includeSubdomains)
    );
  if (e.class === 'ip') return host.kind === 'ip' && ipMatchesLiteral(host.ip, e.ip);
  // e is narrowed to CidrEntry here — no unreachable fallthrough.
  return host.kind === 'ip' && ipMatchesCidr(host.ip, e.version, e.base, e.prefix);
}

// --- path matching -------------------------------------------------------------------------------------------

/** Segment-boundary prefix match: `/api` matches `/api`, `/api/`, `/api/v1`, never `/apiv2`. */
function pathPrefixMatches(path: string, prefix: string): boolean {
  if (prefix === '/') return true;
  if (path === prefix) return true;
  const withSlash = prefix.endsWith('/') ? prefix : prefix + '/';
  return path.startsWith(withSlash);
}

function boundHostMatches(
  host: CanonicalHost,
  boundHostAscii: string,
  boundHostWildcard: boolean,
): boolean {
  return (
    host.kind === 'domain' &&
    domainMatches(host.hostAscii, boundHostAscii, boundHostWildcard, false)
  );
}

// --- exclusion matching --------------------------------------------------------------------------------------

/** Does an exclusion entry match the candidate on its own dimension? Any match ⇒ the whole candidate is denied. */
function exclusionMatches(c: Candidate, e: ScopeEntry): boolean {
  switch (e.class) {
    case 'domain':
    case 'ip':
    case 'cidr':
      return hostEntryMatches(c.host, e);
    case 'port':
      return c.port >= e.low && c.port <= e.high;
    case 'protocol':
      return c.scheme === e.scheme;
    case 'path_prefix':
      return (
        boundHostMatches(c.host, e.boundHostAscii, e.boundHostWildcard) &&
        pathPrefixMatches(c.path, e.pathPrefix)
      );
    case 'api_resource':
      return (
        boundHostMatches(c.host, e.boundHostAscii, e.boundHostWildcard) &&
        e.operations.includes(`${c.method} ${c.path}`)
      );
  }
}

// --- the decision --------------------------------------------------------------------------------------------

export function evaluateScope(
  c: Candidate,
  scope: ScopeVersion,
  ctx: EvalContext = {},
): ScopeDecision {
  const entries = scope.entries;
  const allows = entries.filter((e) => e.isExclusion !== true);
  const excludes = entries.filter((e) => e.isExclusion === true);

  // 1. Scheme. https is default-allowed; other schemes need an explicit protocol allow entry.
  const allowedSchemes = new Set<Scheme>([DEFAULT_ALLOWED_SCHEME]);
  for (const e of allows) if (e.class === 'protocol') allowedSchemes.add(e.scheme);
  if (!allowedSchemes.has(c.scheme)) return DENY('scheme_not_allowed');

  // 2. IP-literal network guard — Tier A is absolute.
  let ipTier: 'hard_deny' | 'restricted' | 'permitted' | null = null;
  if (c.host.kind === 'ip') {
    const verdict = classifyBytes(c.host.ip);
    if (verdict.tier === 'hard_deny') return DENY(`network_guard:${verdict.reason}`);
    ipTier = verdict.tier;
  }

  // 3. Exclusions first — any matching exclusion denies, even over an allow.
  for (const e of excludes) if (exclusionMatches(c, e)) return DENY('excluded');

  // 4. Host allow-match (deny-by-default). Tier B needs a matching ELEVATED entry + elevation context.
  const hostAllows = allows.filter(isHostEntry).filter((e) => hostEntryMatches(c.host, e));
  if (hostAllows.length === 0) return DENY('no_host_match');
  if (ipTier === 'restricted') {
    const elevatedMatch = hostAllows.some((e) => e.elevated === true);
    if (!elevatedMatch) return DENY('restricted_range_not_elevated');
    if (ctx.elevationGranted !== true) return DENY('restricted_range_elevation_not_granted');
  }

  // 5a. Port. Explicit port entries define the allowed set; with none, only the scheme-default port is allowed.
  const portEntries = allows.filter((e) => e.class === 'port');
  const portOk =
    portEntries.length > 0
      ? portEntries.some((e) => c.port >= e.low && c.port <= e.high)
      : c.port === SCHEME_DEFAULT_PORT[c.scheme];
  if (!portOk) return DENY('port_not_allowed');

  // 5b. Host-bound path. If the matched host has path_prefix/api_resource allow entries, the path must match one;
  //     a host with no such entries is unconstrained on path.
  const boundPathEntries = allows
    .filter(isBoundPathEntry)
    .filter((e) => boundHostMatches(c.host, e.boundHostAscii, e.boundHostWildcard));
  if (boundPathEntries.length > 0) {
    // e is narrowed to path_prefix | api_resource, so the else-branch is api_resource — no dead fallthrough.
    const pathOk = boundPathEntries.some((e) =>
      e.class === 'path_prefix'
        ? pathPrefixMatches(c.path, e.pathPrefix)
        : e.operations.includes(`${c.method} ${c.path}`),
    );
    if (!pathOk) return DENY('path_not_allowed');
  }

  return ALLOW('in_scope');
}

/** Convenience: canonicalize a raw URL + method and evaluate it against a scope in one call. */
export function evaluateUrl(
  rawUrl: string,
  scope: ScopeVersion,
  method = 'GET',
  ctx: EvalContext = {},
): ScopeDecision {
  const built = candidateFromUrl(rawUrl, method);
  if (!built.ok) return DENY(`uncanonicalizable:${built.reason}`);
  return evaluateScope(built.candidate, scope, ctx);
}
