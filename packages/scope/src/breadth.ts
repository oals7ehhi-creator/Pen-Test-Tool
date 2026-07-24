/**
 * Scope-breadth accounting (Phase 0 §4.6). Broad scope is the quiet path from an authorized assessment to an
 * unauthorized one, so breadth is bounded technically and gated by elevated dual approval. This module computes the
 * breadth metrics over a scope's ALLOW entries and evaluates them against a set of ceilings:
 *
 *   - `hostCount`            distinct hosts named by `domain` + `ip` allow entries (§4.6 "Distinct hosts").
 *   - `ipv4EquivAddresses`  Σ 2^(32 − prefix) over allow IPv4 `ip`/`cidr` entries (a single `ip` = 1) (§4.6).
 *   - `cidrEntryCount`      number of allow `cidr` entries (§4.6).
 *   - `ipv6MinPrefix`       the broadest (smallest) prefix over allow IPv6 `ip`/`cidr` entries, or null if none.
 *
 * Two kinds of limit (§4.2 `cidr_absolute_floor`, §4.6):
 *   - **Absolute floors** — a CIDR broader than the absolute floor (IPv4 `/16`, IPv6 `/32`) is a HARD reject that
 *     no approval can lift. Reported as `hardRejects`.
 *   - **Ceilings** — exceeding an engagement ceiling (or a broader-than-floor CIDR / wildcard domain) requires an
 *     `elevated` entry + dual approval. Reported as `elevationRequired`.
 *
 * This is a pure accounting/validation function: it does not itself grant elevation (that is the approval model in
 * slice 5). It exists so freeze-time validation and the Scope Authority can refuse over-broad scope up front.
 * IPv6 breadth is governed SOLELY by the per-entry prefix floor — never an address sum (a `/64` already holds 2^64
 * addresses, so summing is meaningless, §4.6).
 */

import type { ScopeEntry, ScopeVersion } from './model.js';

/** Absolute CIDR floors that no approval can lift (§4.2 `cidr_absolute_floor`). */
export const ABSOLUTE_MIN_IPV4_PREFIX = 16;
export const ABSOLUTE_MIN_IPV6_PREFIX = 32;

export interface ScopeBreadth {
  readonly hostCount: number;
  readonly ipv4EquivAddresses: number;
  readonly cidrEntryCount: number;
  /** Broadest (numerically smallest) IPv6 prefix across allow IPv6 ip/cidr entries; null if there are none. */
  readonly ipv6MinPrefix: number | null;
}

/** Engagement breadth ceilings (mirror `engagement.max_*` / `min_*`, §2.1, §4.6). */
export interface BreadthCeilings {
  readonly maxScopeHosts: number;
  readonly maxIpv4EquivAddresses: number;
  readonly maxCidrEntries: number;
  readonly minIpv4Prefix: number;
  readonly minIpv6Prefix: number;
}

export interface BreadthViolation {
  readonly dimension: string;
  readonly detail: string;
}

export interface BreadthReport {
  readonly breadth: ScopeBreadth;
  /** Breadth that exceeds an absolute floor — hard reject, not liftable by any approval. */
  readonly hardRejects: readonly BreadthViolation[];
  /** Breadth that exceeds a ceiling / is broad — permitted ONLY with an elevated entry + dual approval. */
  readonly elevationRequired: readonly BreadthViolation[];
}

const isAllow = (e: ScopeEntry): boolean => e.isExclusion !== true;

/** Compute the four breadth metrics over a scope's allow entries (§4.6). */
export function computeScopeBreadth(scope: ScopeVersion): ScopeBreadth {
  const allows = scope.entries.filter(isAllow);

  const domainHosts = new Set<string>();
  const ipHosts = new Set<string>();
  let ipv4EquivAddresses = 0;
  let cidrEntryCount = 0;
  let ipv6MinPrefix: number | null = null;

  const noteIpv6Prefix = (prefix: number): void => {
    ipv6MinPrefix = ipv6MinPrefix === null ? prefix : Math.min(ipv6MinPrefix, prefix);
  };

  for (const e of allows) {
    switch (e.class) {
      case 'domain':
        domainHosts.add(e.hostAscii);
        break;
      case 'ip':
        ipHosts.add(e.ip);
        // A single literal counts as one host and (if IPv4) one address; IPv6 contributes to the prefix floor.
        if (e.ip.includes(':')) noteIpv6Prefix(128);
        else ipv4EquivAddresses += 1;
        break;
      case 'cidr':
        cidrEntryCount += 1;
        if (e.version === 4) ipv4EquivAddresses += 2 ** (32 - e.prefix);
        else noteIpv6Prefix(e.prefix);
        break;
      default:
        break; // port / protocol / path_prefix / api_resource do not contribute to breadth
    }
  }

  return {
    hostCount: domainHosts.size + ipHosts.size,
    ipv4EquivAddresses,
    cidrEntryCount,
    ipv6MinPrefix,
  };
}

/**
 * Evaluate a scope's breadth against ceilings (§4.6). Returns the computed breadth plus two violation lists:
 * `hardRejects` (broader than an absolute floor — no approval can lift) and `elevationRequired` (over a ceiling or
 * otherwise broad — needs an elevated entry + dual approval). An empty `elevationRequired` AND empty `hardRejects`
 * means the scope is within ordinary limits.
 */
export function evaluateBreadth(scope: ScopeVersion, ceilings: BreadthCeilings): BreadthReport {
  const breadth = computeScopeBreadth(scope);
  const hardRejects: BreadthViolation[] = [];
  const elevationRequired: BreadthViolation[] = [];

  for (const e of scope.entries.filter(isAllow)) {
    if (e.class === 'cidr') {
      if (e.version === 4) {
        if (e.prefix < ABSOLUTE_MIN_IPV4_PREFIX)
          hardRejects.push({
            dimension: 'ipv4_prefix',
            detail: `/${e.prefix} < absolute floor /${ABSOLUTE_MIN_IPV4_PREFIX}`,
          });
        else if (e.prefix < ceilings.minIpv4Prefix)
          elevationRequired.push({
            dimension: 'ipv4_prefix',
            detail: `/${e.prefix} < engagement floor /${ceilings.minIpv4Prefix}`,
          });
      } else {
        if (e.prefix < ABSOLUTE_MIN_IPV6_PREFIX)
          hardRejects.push({
            dimension: 'ipv6_prefix',
            detail: `/${e.prefix} < absolute floor /${ABSOLUTE_MIN_IPV6_PREFIX}`,
          });
        else if (e.prefix < ceilings.minIpv6Prefix)
          elevationRequired.push({
            dimension: 'ipv6_prefix',
            detail: `/${e.prefix} < engagement floor /${ceilings.minIpv6Prefix}`,
          });
      }
    }
    // A wildcard domain authorizes a whole subtree and always requires elevation (§4.4, §4.6).
    if (e.class === 'domain' && e.wildcard)
      elevationRequired.push({ dimension: 'wildcard_domain', detail: e.hostAscii });
  }

  if (breadth.hostCount > ceilings.maxScopeHosts)
    elevationRequired.push({
      dimension: 'host_count',
      detail: `${breadth.hostCount} > ${ceilings.maxScopeHosts}`,
    });
  if (breadth.ipv4EquivAddresses > ceilings.maxIpv4EquivAddresses)
    elevationRequired.push({
      dimension: 'ipv4_equiv_addresses',
      detail: `${breadth.ipv4EquivAddresses} > ${ceilings.maxIpv4EquivAddresses}`,
    });
  if (breadth.cidrEntryCount > ceilings.maxCidrEntries)
    elevationRequired.push({
      dimension: 'cidr_entry_count',
      detail: `${breadth.cidrEntryCount} > ${ceilings.maxCidrEntries}`,
    });

  return { breadth, hardRejects, elevationRequired };
}
