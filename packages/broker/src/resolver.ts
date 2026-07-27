/**
 * Broker-side DNS resolution (Phase 0 §7.1 step 11 / doc 10 §4.1). The broker is the ONLY component that resolves a
 * target's DNS — clients never do — and the resolved set feeds `resolveAndPin`, which guards EVERY address and pins one.
 * This adapter is the thin, injectable boundary to the real resolver: it resolves both A (v4) and AAAA (v6), merges
 * them (deduped), and NEVER throws on a partial answer (a host with only A records, or only AAAA, is normal — a NODATA
 * on one family must not fail the whole resolution). An empty merged result is returned as-is so `resolveAndPin` can
 * fail closed with `no_resolution`.
 *
 * `dns.resolve4/6` (NOT `dns.lookup`) is used deliberately: it queries DNS directly and does NOT consult the OS hosts
 * file, so a `127.0.0.1`-in-/etc/hosts entry cannot smuggle a loopback answer past the resolver — and every returned
 * address is still re-guarded at pin time regardless.
 */

import { promises as dns } from 'node:dns';

/** The DNS primitive the adapter depends on (injectable; default binds to `node:dns`). */
export interface DnsResolver {
  readonly resolve4: (host: string) => Promise<readonly string[]>;
  readonly resolve6: (host: string) => Promise<readonly string[]>;
}

/* v8 ignore next 4 -- trivial pass-through to the node:dns I/O boundary; exercised live, not in the offline suite. */
export const nodeDnsResolver: DnsResolver = {
  resolve4: (host) => dns.resolve4(host),
  resolve6: (host) => dns.resolve6(host),
};

/**
 * Build the broker's resolve function for `ResolveContext.resolve`: resolve A + AAAA concurrently, merge deduped,
 * and treat a per-family failure (NODATA / NXDOMAIN on one family) as "no addresses from that family" rather than a
 * hard error — only a total absence yields an empty list (⇒ `resolveAndPin` denies `no_resolution`).
 */
export function createResolver(
  resolver: DnsResolver = nodeDnsResolver,
): (host: string) => Promise<readonly string[]> {
  return async (host: string): Promise<readonly string[]> => {
    const [v4, v6] = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
    const merged = new Set<string>();
    for (const settled of [v4, v6]) {
      if (settled.status === 'fulfilled') for (const addr of settled.value) merged.add(addr);
    }
    return [...merged];
  };
}
