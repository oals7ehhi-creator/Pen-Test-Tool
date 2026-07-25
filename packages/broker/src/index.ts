/**
 * @pentest/broker — the Guarded Egress Broker's pure decision core (Phase 2, slice 4c).
 *
 * The broker is the ONLY component that opens a socket to a target (Phase 0 doc 10 §4). This package implements its
 * connect-time security decisions as pure, injectable-I/O logic:
 *   - `authorizeIngress` — per-job identity + single-use, spec-bound grant (§4.3 / §7.1 step 6–7);
 *   - `resolveAndPin` / `guardResolvedIp` — resolve the canonical host, guard EVERY resolved address (§6) + honour
 *     scope exclusions + Tier B elevation, and PIN one validated IP (DNS-rebinding / SSRF-at-connect defense, §7.1
 *     step 11);
 *   - `guardRedirect` — never auto-follow a 3xx; re-decide the Location against the frozen scope (§7.1 step 13).
 *
 * The actual mTLS ingress, DNS/TCP/TLS sockets, and the budget/window/e-stop interlocks are wired in later
 * (slice 4c-transport / slice 5); the resolver and grant-jti consumer are injected so nothing here performs real
 * egress. Redirects are never followed in place — each hop demands a fresh spec + grant + resolve/pin.
 */

export {
  type ResolveContext,
  type IpGuardResult,
  type PinDecision,
  guardResolvedIp,
  resolveAndPin,
} from './resolvePin.js';

export { type JobIdentity, IngressError, authorizeIngress } from './ingress.js';

export { type RedirectContext, type RedirectDecision, guardRedirect } from './redirect.js';
