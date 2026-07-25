/**
 * Resolve → validate → PIN (Phase 0 §7.1 step 11 / doc 10 §3 steps 6–8). The Guarded Egress Broker is the only
 * component that opens a target socket, and this is its connect-time network-safety gate — the DNS-rebinding and
 * SSRF-at-connect defense that the spec-time scope decision (which ran against the DOMAIN) cannot provide:
 *
 *   1. resolve the canonical host through an INJECTABLE resolver (the broker resolves; clients never do — §4.1);
 *   2. EVERY resolved address must pass the two-tier network guard (§6) AND must not hit a scope exclusion — a
 *      mixed A/AAAA set (some good, some Tier-A/excluded) is treated as a rebinding attack and the whole
 *      connection is refused (fail closed), never "pick the good one";
 *   3. PIN one validated address; the connect step dials ONLY that pinned IP and never re-resolves, so an attacker
 *      cannot flip DNS between validation and connect (TOCTOU / DNS-rebinding).
 *
 * The domain's membership in scope was already established when the request_spec was built (the allowlist match on
 * `canonical_host`); here we re-guard the *resolved* address: Tier A is an absolute deny, Tier B is denied unless a
 * matching `elevated` ip/cidr entry exists AND elevation is granted, any ip/cidr EXCLUSION denies, and anything the
 * resolver returns that cannot be parsed as an IP is denied. No allow-list *positive* is required here — a public
 * host legitimately resolves to an address the operator never enumerated; the guard just proves it is not forbidden.
 */

import {
  parseIpLiteral,
  classifyBytes,
  inCidrV4,
  inCidrV6,
  embeddedV4,
  type ParsedIp,
  type ScopeVersion,
  type ScopeEntry,
} from '@pentest/scope';

export interface ResolveContext {
  /** The frozen scope this request was specced against. */
  readonly scope: ScopeVersion;
  /** True when the full Tier B elevation precondition holds for this engagement (resolved by the Scope Authority). */
  readonly elevationGranted?: boolean;
  /** Broker-side DNS resolution (injectable). Returns the resolved address strings (A/AAAA). */
  readonly resolve: (host: string) => Promise<readonly string[]>;
}

export type IpGuardResult = { readonly ok: true } | { readonly ok: false; readonly reason: string };

export type PinDecision =
  | { readonly ok: true; readonly pinnedIp: string; readonly resolved: readonly string[] }
  | { readonly ok: false; readonly reason: string; readonly ip?: string };

/** Does one concrete (version,bytes) address fall inside an ip/cidr scope entry? (domain/port/etc. never match.) */
function matchesRepr(version: 4 | 6, bytes: Uint8Array, e: ScopeEntry): boolean {
  if (e.class === 'ip') {
    const lit = parseIpLiteral(e.ip);
    return (
      lit !== null &&
      lit.version === version &&
      lit.bytes.length === bytes.length &&
      lit.bytes.every((b, i) => b === bytes[i])
    );
  }
  if (e.class === 'cidr') {
    if (e.version !== version) return false;
    if (e.version === 4) return inCidrV4(bytes, e.base, e.prefix);
    const base = parseIpLiteral(e.base);
    return base !== null && base.version === 6 && inCidrV6(bytes, base.bytes, e.prefix);
  }
  return false;
}

/**
 * Does a resolved IP fall inside an ip/cidr scope entry? Matches on the SAME decoded representation the network guard
 * (`classifyBytes`) uses: a transition/embedding IPv6 form (`::ffff:a.b.c.d`, deprecated compat, 6to4, Teredo, NAT64)
 * is ALSO tested as its embedded IPv4, so a v4 ip/cidr entry — critically, an EXCLUSION — cannot be evaded by
 * presenting the address in mapped form (an exclusion must always win, §4.5). Adding the embedded-v4 test can only
 * ADD matches to an address the guard already decodes the same way, never relax a deny.
 */
function ipEntryMatches(ip: ParsedIp, e: ScopeEntry): boolean {
  if (matchesRepr(ip.version, ip.bytes, e)) return true;
  if (ip.version === 6) {
    const emb = embeddedV4(ip.bytes);
    if (emb !== null && matchesRepr(4, emb, e)) return true;
  }
  return false;
}

/**
 * Connect-time guard for ONE resolved address (§6 + exclusions-first + Tier B elevation). Fails closed: anything
 * unparseable, Tier A, excluded, or Tier B without a matching elevated entry + granted elevation is denied.
 */
export function guardResolvedIp(ipStr: string, ctx: ResolveContext): IpGuardResult {
  const ip = parseIpLiteral(ipStr);
  if (ip === null) return { ok: false, reason: 'unparseable_ip' };

  const verdict = classifyBytes(ip);
  if (verdict.tier === 'hard_deny') return { ok: false, reason: `network_guard:${verdict.reason}` };

  // Exclusions always win — a resolved address hitting any ip/cidr exclusion is denied even if otherwise permitted.
  // (`ipEntryMatches` returns false for non-ip/cidr entries, so a domain/port exclusion never matches an IP here.)
  for (const e of ctx.scope.entries) {
    if (e.isExclusion === true && ipEntryMatches(ip, e)) {
      return { ok: false, reason: 'excluded' };
    }
  }

  if (verdict.tier === 'restricted') {
    // Tier B (RFC1918/ULA/link-local/CGNAT): reachable only via a matching ELEVATED ip/cidr entry + granted elevation.
    // An elevated DOMAIN entry does NOT count — `ipEntryMatches` matches only literal ip/cidr entries, so network-tier
    // elevation must be enumerated as an ip/cidr; a broad elevated domain can never open a private resolution.
    const elevatedMatch = ctx.scope.entries.some(
      (e) => e.isExclusion !== true && e.elevated === true && ipEntryMatches(ip, e),
    );
    if (!elevatedMatch) return { ok: false, reason: 'restricted_range_not_elevated' };
    if (ctx.elevationGranted !== true)
      return { ok: false, reason: 'restricted_range_elevation_not_granted' };
  }

  return { ok: true };
}

/**
 * Resolve a canonical host and pin a validated address, or deny. EVERY resolved address must pass `guardResolvedIp`;
 * if any fails, the whole connection is refused (a mixed result is a rebinding signal). An empty resolution is denied.
 * The pinned address is returned in canonical form; the caller must dial ONLY it (no re-resolution).
 */
export async function resolveAndPin(host: string, ctx: ResolveContext): Promise<PinDecision> {
  const resolved = await ctx.resolve(host);
  if (resolved.length === 0) return { ok: false, reason: 'no_resolution' };

  for (const ipStr of resolved) {
    const g = guardResolvedIp(ipStr, ctx);
    if (!g.ok) return { ok: false, reason: g.reason, ip: ipStr };
  }

  // All validated → pin the first (canonicalized). parseIpLiteral cannot be null here (it passed the guard).
  const pinned = parseIpLiteral(resolved[0]!);
  /* v8 ignore next -- unreachable: resolved[0] already parsed successfully inside guardResolvedIp */
  if (pinned === null) return { ok: false, reason: 'unparseable_ip' };
  return { ok: true, pinnedIp: pinned.canonical, resolved };
}
