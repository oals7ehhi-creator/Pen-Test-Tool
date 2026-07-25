/**
 * Redirect re-guard (Phase 0 §7.1 step 13 / doc 10 §3 step 10). The broker NEVER auto-follows a 3xx. Instead each
 * hop is treated as a brand-new request: the `Location` is canonicalized and re-decided against the frozen scope,
 * and only an in-scope target yields a NEW candidate for which the caller must form a fresh `request_spec` and
 * obtain a FRESH single-use grant before another resolve→pin→connect. An out-of-scope or off-limits redirect gets
 * no grant → the chain stops. Hop depth is bounded so a redirect loop cannot spin forever.
 *
 * This defeats redirect-based SSRF (a 200-in-scope page 302-ing to `http://169.254.169.254/`): the Location is
 * decided by the SAME deny-by-default scope evaluator, so metadata / loopback / out-of-scope hosts are refused, and
 * because a fresh grant + fresh resolve/pin is required, the DNS-rebinding defense applies to every hop too.
 */

import {
  evaluateUrl,
  type ScopeVersion,
  type EvalContext,
  type CanonicalUrl,
  canonicalizeUrl,
} from '@pentest/scope';

export interface RedirectContext {
  readonly scope: ScopeVersion;
  readonly eval?: EvalContext;
  /** The current hop number (0 = the original request). */
  readonly hop: number;
  /** Maximum redirect hops permitted before the chain is stopped. */
  readonly maxHops: number;
}

export type RedirectDecision =
  | { readonly follow: true; readonly next: CanonicalUrl }
  | { readonly follow: false; readonly reason: string };

/**
 * Decide a single redirect hop. Returns `follow:true` with the canonical next target (for which the caller mints a
 * FRESH spec + grant — this function never opens a socket) when the Location is in scope and the hop budget remains;
 * otherwise `follow:false` with a fixed reason. `method` is GET for a followed redirect target.
 */
export function guardRedirect(location: string, ctx: RedirectContext): RedirectDecision {
  if (ctx.hop >= ctx.maxHops) return { follow: false, reason: 'redirect_depth_exceeded' };

  const parsed = canonicalizeUrl(location);
  if (!parsed.ok) return { follow: false, reason: `redirect_uncanonicalizable:${parsed.reason}` };

  const decision = evaluateUrl(location, ctx.scope, 'GET', ctx.eval ?? {});
  if (!decision.allow) return { follow: false, reason: `redirect_out_of_scope:${decision.reason}` };

  return { follow: true, next: parsed.url };
}
