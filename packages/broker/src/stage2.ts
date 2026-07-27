/**
 * Stage-2 orchestration (Phase 0 §7.1 steps 7–13 / doc 10 §3). This threads the broker's already-built, individually
 * reviewed decision steps into the one end-to-end procedure the Guarded Egress Broker runs per request. The ORDER is a
 * security property, not a convenience:
 *
 *   7.  VERIFY GRANT + IDENTITY   — the presented spec's digest is recomputed and the grant must bind it; the grant's
 *                                    tenant/engagement/run/job must equal the calling job (single-use jti consumed).
 *   8.  RECONSTRUCT               — rebuild the wire request from the immutable spec (never a worker-serialized one).
 *   9-10. INTERLOCKS (slice 5)    — an injected `beforeEgress` hook runs AFTER reconstruct and BEFORE any egress
 *                                    (state re-check + budget charge). It may deny; on denial NO socket is opened.
 *   11. RESOLVE + PIN             — resolve the canonical host, guard every address, pin one (rebinding defense).
 *   12. CONNECT + SEND            — dial ONLY the pinned IP; serialize and send exactly the reconstructed request.
 *   13. REDIRECT                  — a 3xx is NEVER auto-followed; its Location is re-decided against the frozen scope
 *                                    and returned as a NEW candidate for a fresh spec + grant.
 *
 * Every dependency is injected, so this is pure composition — the grant key/clock, the catalog/secret resolvers, the
 * DNS resolver, the socket connectors, and the interlock hook are all supplied by the caller. A failure at any step
 * short-circuits with a fixed `{stage, reason}` (never response/secret content), and — critically — a denial before
 * step 12 opens no socket at all.
 */

import {
  computeSpecSha256,
  GrantError,
  type RequestSpecContent,
  type GrantClaims,
  type VerifyGrantParams,
} from '@pentest/spec';
import { authorizeIngress, IngressError, type JobIdentity } from './ingress.js';
import {
  reconstructRequest,
  ReconstructError,
  type ReconstructContext,
  type ReconstructedRequest,
} from './reconstruct.js';
import type { Duplex } from 'node:stream';
import { resolveAndPin, type ResolveContext, type PinDecision } from './resolvePin.js';
import { connectPinned, type Connectors } from './connect.js';
import {
  serializeRequest,
  readBoundedResponse,
  WireError,
  type ReadOptions,
  type HttpResponse,
} from './wire.js';
import { guardRedirect, type RedirectContext, type RedirectDecision } from './redirect.js';

/** What a Stage-2 run is given: the calling job's identity, its egress grant, and the immutable spec it presents. */
export interface Stage2Input {
  readonly identity: JobIdentity;
  readonly grantToken: string;
  readonly spec: RequestSpecContent;
  /** The redirect hop number (0 = the original request); bounded by `redirect.maxHops`. */
  readonly hop?: number;
}

/** All injected I/O + policy the Stage-2 procedure depends on. */
export interface Stage2Deps {
  /** Grant verification params EXCEPT `presentedSpecSha256`, which Stage-2 recomputes from the presented spec. */
  readonly grantVerify: Omit<VerifyGrantParams, 'presentedSpecSha256'>;
  readonly reconstruct: ReconstructContext;
  /**
   * Interlocks (§7.1 steps 9–10, slice 5): runs AFTER reconstruct and BEFORE any egress. Throw to DENY — no socket is
   * opened, so a denial here guarantees no packet leaves (SI-055). REQUIRED so the composition cannot reach egress
   * without the interlock slot being invoked; slice 5 fills it with the real state-recheck + budget charge, and a
   * caller that has no interlock must pass an EXPLICIT no-op (a conscious, visible choice — never a silent default).
   */
  readonly beforeEgress: (ctx: {
    readonly claims: GrantClaims;
    readonly request: ReconstructedRequest;
  }) => void | Promise<void>;
  readonly resolve: ResolveContext;
  readonly connectors?: Connectors;
  readonly read: ReadOptions;
  /** Redirect re-guard context EXCEPT `hop`, which comes from the input. */
  readonly redirect: Omit<RedirectContext, 'hop'>;
}

export type Stage2Outcome =
  | {
      readonly ok: true;
      readonly claims: GrantClaims;
      readonly request: ReconstructedRequest;
      readonly pinnedIp: string;
      readonly response: HttpResponse;
      /** For a 3xx response: the re-guard decision (NEVER auto-followed). Null when the response is not a redirect. */
      readonly redirect: RedirectDecision | null;
    }
  | {
      readonly ok: false;
      /** Which step denied: `ingress` | `reconstruct` | `interlock` | `resolve` | `send` | `read`. */
      readonly stage: 'ingress' | 'reconstruct' | 'interlock' | 'resolve' | 'send' | 'read';
      /** Fixed reason code from the failing step — never response/secret content. */
      readonly reason: string;
    };

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function reasonOf(e: unknown): string {
  if (
    e instanceof GrantError ||
    e instanceof IngressError ||
    e instanceof ReconstructError ||
    e instanceof WireError
  ) {
    return e.reason;
  }
  // The interlock hook (slice 5) denies with a fixed-reason error (e.g. BudgetError) — surface its code so the
  // interlock stage reports `budget_exhausted` / `emergency_stop` rather than a generic `error`. Our reason codes are
  // always fixed tokens (never response/secret content), so echoing a string `reason` here cannot leak.
  if (typeof (e as { reason?: unknown }).reason === 'string') {
    return (e as { reason: string }).reason;
  }
  return 'error';
}

function headerValue(res: HttpResponse, name: string): string | null {
  for (const h of res.headers) if (h.name.toLowerCase() === name) return h.value;
  return null;
}

/** Run the Stage-2 procedure end-to-end. Returns a success with the (bounded) response, or a fixed `{stage, reason}`. */
export async function runStage2(input: Stage2Input, deps: Stage2Deps): Promise<Stage2Outcome> {
  // 7. VERIFY GRANT + IDENTITY — bind the grant to THIS exact spec (recompute its digest) and to the calling job.
  const presentedSpecSha256 = computeSpecSha256(input.spec);
  let claims: GrantClaims;
  try {
    claims = await authorizeIngress(input.identity, input.grantToken, {
      ...deps.grantVerify,
      presentedSpecSha256,
    });
  } catch (e) {
    return { ok: false, stage: 'ingress', reason: reasonOf(e) };
  }

  // 8. RECONSTRUCT — deterministically rebuild the wire request from the immutable spec.
  let request: ReconstructedRequest;
  try {
    request = await reconstructRequest(input.spec, deps.reconstruct);
  } catch (e) {
    return { ok: false, stage: 'reconstruct', reason: reasonOf(e) };
  }

  // 9–10. INTERLOCKS — state re-check + budget charge BEFORE any egress. The hook is REQUIRED (fail-closed by
  // construction): the composition cannot reach DNS/connect without it having run. A denial here opens no socket.
  try {
    await deps.beforeEgress({ claims, request });
  } catch (e) {
    return { ok: false, stage: 'interlock', reason: reasonOf(e) };
  }

  // 11. RESOLVE + PIN — the FIRST egress; guard every resolved address, pin one validated IP.
  let pin: PinDecision;
  try {
    pin = await resolveAndPin(request.host, deps.resolve);
  } catch (e) {
    return { ok: false, stage: 'resolve', reason: reasonOf(e) };
  }
  if (!pin.ok) return { ok: false, stage: 'resolve', reason: pin.reason };

  // 12. CONNECT + SEND — dial ONLY the pinned IP and issue exactly the reconstructed request.
  const useTls = request.scheme === 'https' || request.scheme === 'wss';
  let socket: Duplex | undefined;
  try {
    socket = connectPinned(
      pin.pinnedIp,
      { host: request.host, port: request.port, tls: useTls },
      deps.connectors,
    );
    socket.write(serializeRequest(request));
  } catch (e) {
    // A synchronous throw after the socket was created (e.g. from serialize/write) must not leak an open socket.
    socket?.destroy();
    return { ok: false, stage: 'send', reason: reasonOf(e) };
  }

  // read the bounded response.
  let response: HttpResponse;
  try {
    response = await readBoundedResponse(socket, {
      ...deps.read,
      headRequest: request.method === 'HEAD',
    });
  } catch (e) {
    return { ok: false, stage: 'read', reason: reasonOf(e) };
  }

  // 13. REDIRECT — never auto-follow; re-decide a 3xx Location against the frozen scope for a fresh spec + grant.
  let redirect: RedirectDecision | null = null;
  if (REDIRECT_STATUSES.has(response.statusCode)) {
    const location = headerValue(response, 'location');
    if (location !== null) {
      redirect = guardRedirect(location, { ...deps.redirect, hop: input.hop ?? 0 });
    }
  }

  return { ok: true, claims, request, pinnedIp: pin.pinnedIp, response, redirect };
}
