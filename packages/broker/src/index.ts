/**
 * @pentest/broker — the Guarded Egress Broker's pure decision core (Phase 2, slice 4c).
 *
 * The broker is the ONLY component that opens a socket to a target (Phase 0 doc 10 §4). This package implements its
 * connect-time security decisions as pure, injectable-I/O logic:
 *   - `authorizeIngress` — per-job identity + single-use, spec-bound grant (§4.3 / §7.1 step 6–7);
 *   - `resolveAndPin` / `guardResolvedIp` — resolve the canonical host, guard EVERY resolved address (§6) + honour
 *     scope exclusions + Tier B elevation, and PIN one validated IP (DNS-rebinding / SSRF-at-connect defense, §7.1
 *     step 11);
 *   - `guardRedirect` — never auto-follow a 3xx; re-decide the Location against the frozen scope (§7.1 step 13);
 *   - `reconstructRequest` — rebuild the wire request DETERMINISTICALLY from the immutable spec, verifying every
 *     content-addressed/secret binding before egress (§7.1 step 8, SI-061) — the broker never trusts a worker request;
 *   - `createResolver` / `connectPinned` — the outbound socket layer: resolve A+AAAA (§7.1 step 11, feeds
 *     `resolveAndPin`) and dial ONLY the pinned IP with SNI/cert-identity bound to the canonical host (§7.1 step 12);
 *   - `serializeRequest` / `readBoundedResponse` — the send/read wire: frame the reconstructed request to exact
 *     HTTP/1.1 bytes and read the response under a hard body cap (§7.1 step 12 SEND, §8 max_response_body_bytes);
 *   - `runStage2` — the end-to-end orchestration threading verify-grant → reconstruct → interlocks → resolve/pin →
 *     connect/send → bounded-read → redirect-re-guard in the security-critical order (§7.1 steps 7–13);
 *   - `authorizeConnection` / `buildIngressServerOptions` — the mTLS ingress decision: verify the per-job client cert
 *     and extract the `JobIdentity` that the grant must equal (doc 10 §4.3 / §7.1 step 6).
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

export {
  type HeaderField,
  type HeaderSet,
  type Payload,
  type QueryTemplate,
  type SessionLease,
  type QueryValueLease,
  type ReconstructContext,
  type ReconstructReason,
  type ReconstructedRequest,
  ReconstructError,
  reconstructRequest,
} from './reconstruct.js';

export { type DnsResolver, nodeDnsResolver, createResolver } from './resolver.js';

export {
  type ConnectTarget,
  type Connectors,
  nodeConnectors,
  buildTcpOptions,
  buildTlsOptions,
  connectPinned,
} from './connect.js';

export {
  type HttpResponse,
  type ReadOptions,
  type WireReason,
  WireError,
  serializeRequest,
  readBoundedResponse,
} from './wire.js';

export { type Stage2Input, type Stage2Deps, type Stage2Outcome, runStage2 } from './stage2.js';

export {
  type BudgetDenyReason,
  type ChargeRequest,
  type ChargeReceipt,
  type ChargeOutcome,
  type BudgetLedger,
  type BudgetInterlockConfig,
  BudgetError,
  createBudgetInterlock,
} from './budget.js';

export {
  type LiveStateReason,
  type RecurringWindow,
  type AbsoluteWindow,
  type TestingWindow,
  type LiveStateContext,
  type LiveStateResult,
  type BeforeEgressHook,
  LiveStateError,
  evaluateLiveState,
  createLiveStateGate,
  composeBeforeEgress,
} from './livestate.js';

export {
  type CircuitState,
  type ThrottleReason,
  type ThrottleConfig,
  type ThrottleSnapshot,
  type AcquireDecision,
  type CircuitUpdate,
  type EngagementRef,
  type AcquireOutcome,
  type ThrottleController,
  ThrottleError,
  evaluateAcquire,
  recordResult,
  createThrottleGate,
} from './throttle.js';

export {
  type RateLimitReason,
  type BucketState,
  type BucketConfig,
  type BucketResult,
  type RateSnapshot,
  type RateConfig,
  type RateDecision,
  type RateRef,
  type RateOutcome,
  type RateLimiter,
  RateLimitError,
  refillAndTake,
  evaluateRateLimit,
  createRateLimitGate,
} from './ratelimit.js';

export {
  type HostConcurrencyReason,
  type HostSlotSnapshot,
  type HostSlotConfig,
  type HostSlotDecision,
  type HostSlotRef,
  type HostSlotReleaseRef,
  type HostSlotOutcome,
  type HostSlotController,
  HostConcurrencyError,
  evaluateHostSlot,
  createHostConcurrencyGate,
} from './hostconc.js';

export {
  type IngressAuthReason,
  type IngressCredentials,
  type VerifiedTlsSocket,
  IngressAuthError,
  buildIngressServerOptions,
  authorizeConnection,
  extractJobIdentity,
} from './ingressServer.js';
