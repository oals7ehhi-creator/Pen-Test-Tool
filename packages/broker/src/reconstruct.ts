/**
 * Broker request RECONSTRUCTION (Phase 0 §7.1 step 8 / doc 10 §3 step 3; SI-061). The Guarded Egress Broker NEVER
 * sends a worker-serialized request — it rebuilds the wire request DETERMINISTICALLY from the immutable, signed
 * `request_spec` (already proven to be the grant's spec at ingress), so a compromised worker cannot inject a deviation.
 *
 * From the spec's content-addressed references + injected secret leases, and BEFORE any egress, the broker:
 *   1. fetches the FIXED safe header-set by its content digest (and refuses a set that smuggles a broker-controlled
 *      header — Host / Content-Length are set by the broker, never by the curated template);
 *   2. fetches the INERT payload by digest (if any) and decodes its bytes;
 *   3. resolves the query VALUES by path — CURATED (a non-secret `query_template` catalog body) or SECRET (resolve
 *      the operator query-value lease, require its non-secret `value_binding` to equal the spec's — a withdrawn/rotated
 *      version fails here — then recompute the KEYED value digest and CONSTANT-TIME compare it to the spec's
 *      `query_value_digest`; a value tamper fails closed) — and requires the resolved keys to equal the spec's;
 *   4. resolves the operator SESSION lease (if any) and requires its non-secret identity digest to equal the spec's
 *      `session_digest` before the secret is ever used;
 *   5. assembles the absolute URL (percent-encoding every injected value so it cannot alter request structure),
 *      RE-CANONICALIZES it, and asserts the re-derived scheme/host/port/path equal the spec's — else
 *      DENY(reconstruction_mismatch).
 *
 * All I/O is INJECTED (catalog fetch, secret resolve, the keyed-digest key); this module performs no egress and opens
 * no socket. Catalog templates are looked up BY their content digest — the store (migration `0003`) content-addresses
 * them at write, so the broker does not re-derive the DB's `jsonb::text` digest here (that cross-engine canonical-JSON
 * is deliberately avoided); the in-broker re-verifications are exactly the secret bindings §7.1 step 8 names.
 */

import { canonicalizeUrl, type CanonicalUrl } from '@pentest/scope';
import { timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  type RequestSpecContent,
  type Method,
  type SpecScheme,
  type OperatorSessionIdentity,
  type OperatorQueryValueIdentity,
  type QueryValueEntry,
  operatorSessionDigest,
  operatorQueryValueBinding,
  computeQueryValueDigest,
} from '@pentest/spec';

// --- Fetched catalog bodies (what the injected content-addressed resolvers return) ---------------------------------

/** One header field of the fixed safe header-set. Names compare case-insensitively. */
export interface HeaderField {
  readonly name: string;
  readonly value: string;
}
/** The curated, fixed safe header-set (a `header_set` catalog_template body). */
export interface HeaderSet {
  readonly headers: readonly HeaderField[];
}
/** An inert request payload (a `payload` catalog_template body); bytes are base64 so any octet is representable. */
export interface Payload {
  readonly mediaType: string;
  readonly bodyBase64: string;
}
/** A curated, NON-secret query value set (a `query_template` catalog_template body). */
export interface QueryTemplate {
  readonly entries: readonly QueryValueEntry[];
}

// --- Resolved secret leases (from the per-job secret manager) ------------------------------------------------------

/** The operator session lease named by `session_ref`: its non-secret identity + the header(s) it materializes into. */
export interface SessionLease {
  readonly identity: OperatorSessionIdentity;
  readonly headers: readonly HeaderField[];
}
/** The operator query-value lease named by `query_value_ref`: its non-secret identity + the actual secret values. */
export interface QueryValueLease {
  readonly identity: OperatorQueryValueIdentity;
  readonly entries: readonly QueryValueEntry[];
}

/** All I/O the reconstruction depends on, injected. The broker binds these to the specific spec's refs. */
export interface ReconstructContext {
  readonly fetchHeaderSet: (digest: string) => Promise<HeaderSet | null>;
  readonly fetchPayload: (digest: string) => Promise<Payload | null>;
  readonly fetchQueryTemplate: (digest: string) => Promise<QueryTemplate | null>;
  readonly resolveSession: () => Promise<SessionLease | null>;
  readonly resolveQueryValues: () => Promise<QueryValueLease | null>;
  /** The broker/authority key for the keyed `query_value_digest` (used only on the secret query path). */
  readonly queryValueHmacKey: Uint8Array;
}

export type ReconstructReason =
  | 'header_set_not_found'
  | 'header_set_forbidden_header'
  | 'payload_not_found'
  | 'query_template_not_found'
  | 'query_path_ambiguous'
  | 'query_values_unavailable'
  | 'query_keys_mismatch'
  | 'query_binding_mismatch'
  | 'query_value_mismatch'
  | 'session_not_found'
  | 'session_mismatch'
  | 'reconstruction_mismatch';

/** A fixed-reason DENY (SI-061 / §7.1 step 8). Carries only the reason code — never a header/value/secret. */
export class ReconstructError extends Error {
  readonly reason: ReconstructReason;
  constructor(reason: ReconstructReason) {
    super(reason);
    this.name = 'ReconstructError';
    this.reason = reason;
  }
}

/** The deterministic wire request the broker will send — assembled and re-validated against the spec. */
export interface ReconstructedRequest {
  readonly method: Method;
  readonly scheme: SpecScheme;
  readonly host: string;
  readonly port: number;
  readonly path: string;
  /** The percent-encoded query string WITHOUT a leading `?` (empty when the spec has no query). */
  readonly query: string;
  /** The absolute URL actually assembled (canonical_url + `?query`), re-canonicalized to equal the spec. */
  readonly targetUrl: string;
  readonly headers: readonly HeaderField[];
  readonly body: Uint8Array | null;
}

/** Broker-controlled headers a supplied header set/lease must never carry (the broker sets them authoritatively). */
const BROKER_CONTROLLED_HEADERS = new Set(['host', 'content-length']);

/** Scheme default ports — used to omit a default port from the reconstructed Host header. */
const DEFAULT_PORT: Record<SpecScheme, number> = { https: 443, http: 80, wss: 443, ws: 80 };

/** RFC 7230 header field-name token: `1*tchar`, no whitespace / controls / separators. */
const HEADER_NAME_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Screen a supplied header NAME (from either the curated set or the operator-session lease). Rejects a malformed name
 * (so `"host "`, control chars, or an embedded `:` cannot slip a broker-controlled header past the lowercase Set
 * lookup) and any broker-controlled header (Host / Content-Length are set authoritatively). Fixed reason code only.
 */
function screenHeaderName(name: string): void {
  if (!HEADER_NAME_TOKEN.test(name) || BROKER_CONTROLLED_HEADERS.has(name.toLowerCase())) {
    throw new ReconstructError('header_set_forbidden_header');
  }
}

/**
 * Reconstruct the outbound request from the immutable spec (throws `ReconstructError` on any mismatch, BEFORE egress).
 * The spec MUST already be the one bound by the grant (its `spec_sha256` verified at ingress); this rebuilds and
 * re-validates the wire request the broker will actually send.
 */
export async function reconstructRequest(
  spec: RequestSpecContent,
  ctx: ReconstructContext,
): Promise<ReconstructedRequest> {
  // 1. Fixed safe header-set (always present). Reject a curated set that smuggles a broker-controlled/malformed header.
  const headerSet = await ctx.fetchHeaderSet(spec.headerSetDigest);
  if (headerSet === null) throw new ReconstructError('header_set_not_found');
  for (const h of headerSet.headers) screenHeaderName(h.name);

  // 2. Inert payload (optional) → bytes.
  let body: Uint8Array | null = null;
  if (spec.payloadDigest !== null) {
    const payload = await ctx.fetchPayload(spec.payloadDigest);
    if (payload === null) throw new ReconstructError('payload_not_found');
    body = new Uint8Array(Buffer.from(payload.bodyBase64, 'base64'));
  }

  // 3. Query values by path (curated XOR secret), keyed/bound-verified before use.
  const query = await buildQuery(spec, ctx);

  // 4. Operator session (optional): the non-secret identity digest MUST equal the spec's before the secret is used.
  let sessionHeaders: readonly HeaderField[] = [];
  if (spec.sessionDigest !== null) {
    const lease = await ctx.resolveSession();
    if (lease === null) throw new ReconstructError('session_not_found');
    if (!constantTimeHexEqual(operatorSessionDigest(lease.identity), spec.sessionDigest)) {
      throw new ReconstructError('session_mismatch');
    }
    // The session lease is secret-manager data, NOT the immutable spec — it gets the SAME broker-controlled-header
    // screen as the curated set, so a lease cannot smuggle a Host / Content-Length the broker must own authoritatively.
    for (const h of lease.headers) screenHeaderName(h.name);
    sessionHeaders = lease.headers;
  }

  // 5. Assemble + RE-CANONICALIZE; the re-derived structure MUST equal the spec (defends the spec's own consistency).
  const targetUrl = query === '' ? spec.canonicalUrl : `${spec.canonicalUrl}?${query}`;
  const canon = canonicalizeUrl(targetUrl);
  if (!canon.ok || !matchesSpec(canon.url, spec)) {
    throw new ReconstructError('reconstruction_mismatch');
  }

  // 6. Broker-controlled headers first (Host, and Content-Length when there is a body), then the fixed set + session.
  const headers: HeaderField[] = [{ name: 'host', value: hostHeaderValue(canon.url, spec) }];
  if (body !== null) headers.push({ name: 'content-length', value: String(body.length) });
  headers.push(...headerSet.headers, ...sessionHeaders);

  return {
    method: spec.method,
    scheme: spec.scheme,
    host: spec.canonicalHost,
    port: spec.port,
    path: spec.canonicalPath,
    query,
    targetUrl,
    headers,
    body,
  };
}

/**
 * Build the percent-encoded query string. Fails closed on any inconsistency: exactly one of the curated
 * (`query_template_digest`) or secret (`query_value_binding` + `query_value_digest`) paths must supply values for the
 * spec's canonical keys, in order. On the secret path the version binding is checked and the value digest is
 * recomputed + CONSTANT-TIME compared before the values are used.
 */
async function buildQuery(spec: RequestSpecContent, ctx: ReconstructContext): Promise<string> {
  const keys = parseCanonicalKeys(spec.queryKeysCanonical);
  const curated = spec.queryTemplateDigest !== null;
  const secret = spec.queryValueBinding !== null && spec.queryValueDigest !== null;

  // Fail closed on an inconsistent query shape: a declared query path (curated or secret) with NO canonical keys would
  // otherwise silently drop the query — and, worse, skip the secret binding/HMAC verification. DENY instead.
  if (keys.length === 0) {
    if (curated || secret) throw new ReconstructError('query_path_ambiguous');
    return '';
  }
  if (curated === secret) throw new ReconstructError('query_path_ambiguous'); // neither, or both

  let entries: readonly QueryValueEntry[];
  if (curated) {
    const tmpl = await ctx.fetchQueryTemplate(spec.queryTemplateDigest as string);
    if (tmpl === null) throw new ReconstructError('query_template_not_found');
    entries = tmpl.entries;
  } else {
    const lease = await ctx.resolveQueryValues();
    if (lease === null) throw new ReconstructError('query_values_unavailable');
    if (
      !constantTimeHexEqual(
        operatorQueryValueBinding(lease.identity),
        spec.queryValueBinding as string,
      )
    ) {
      throw new ReconstructError('query_binding_mismatch');
    }
    const digest = computeQueryValueDigest(ctx.queryValueHmacKey, lease.entries);
    if (!constantTimeHexEqual(digest, spec.queryValueDigest as string)) {
      throw new ReconstructError('query_value_mismatch');
    }
    entries = lease.entries;
  }

  if (entries.length !== keys.length || entries.some((e, i) => e.key !== keys[i])) {
    throw new ReconstructError('query_keys_mismatch');
  }
  return entries
    .map((e) => `${encodeURIComponent(e.key)}=${encodeURIComponent(e.value)}`)
    .join('&');
}

/** The canonical query KEY list is the ordered `&`-joined parameter names (empty/`null` ⇒ no query). */
function parseCanonicalKeys(canonical: string | null): readonly string[] {
  if (canonical === null || canonical === '') return [];
  return canonical.split('&');
}

/**
 * The authoritative Host header the broker sets: the canonical host (IPv6 bracketed) plus the port when it is not the
 * scheme default. Computed from the re-canonicalized URL, so it always agrees with what will actually be dialed.
 */
function hostHeaderValue(url: CanonicalUrl, spec: RequestSpecContent): string {
  const isV6 = url.host.kind === 'ip' && url.host.ip.version === 6;
  const hostPart = isV6 ? `[${spec.canonicalHost}]` : spec.canonicalHost;
  return spec.port === DEFAULT_PORT[spec.scheme] ? hostPart : `${hostPart}:${spec.port}`;
}

/** The re-canonicalized URL must re-derive exactly the spec's canonical scheme/host/port/path. */
function matchesSpec(url: CanonicalUrl, spec: RequestSpecContent): boolean {
  if (url.scheme !== spec.scheme) return false;
  if (url.port !== spec.port) return false;
  if (url.path !== spec.canonicalPath) return false;
  const host = url.host.kind === 'domain' ? url.host.hostAscii : url.host.ip.canonical;
  return host === spec.canonicalHost;
}

/** Constant-time equality of two hex digests. Length differs only on malformed input (digests are fixed-width). */
function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
