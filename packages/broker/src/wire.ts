/**
 * The Broker's send/read wire layer (Phase 0 §7.1 step 12 "SEND" + §8 `max_response_body_bytes`). After
 * `connectPinned` opens the socket to the pinned IP, this serializes the reconstructed request to exact HTTP/1.1 bytes
 * and reads the response under a HARD body cap.
 *
 * Two safety properties matter here:
 *   1. the broker sends EXACTLY the reconstructed request (already rebuilt from the immutable spec, §7.1 step 8) — this
 *      module only frames those bytes, it invents nothing;
 *   2. the response is bounded: the header section and the body each have a byte ceiling, and an oversize body is
 *      TRUNCATED (flagged) with the socket destroyed — it is never fully buffered (§8 "oversize bodies never fully
 *      buffered"). Content-Length, chunked, and connection-close framings are all capped identically.
 *
 * This module opens no socket of its own; it operates on the injected `Duplex` from `connectPinned`.
 */

import type { Duplex } from 'node:stream';
import { Buffer } from 'node:buffer';
import type { HeaderField, ReconstructedRequest } from './reconstruct.js';

const CRLF = '\r\n';

/** Serialize a reconstructed request to its exact HTTP/1.1 wire bytes (origin-form request-target). */
export function serializeRequest(req: ReconstructedRequest): Uint8Array {
  const target = req.query === '' ? req.path : `${req.path}?${req.query}`;
  const lines: string[] = [`${req.method} ${target} HTTP/1.1`];
  for (const h of req.headers) lines.push(`${h.name}: ${h.value}`);
  const head = Buffer.from(lines.join(CRLF) + CRLF + CRLF, 'utf8');
  const body = req.body === null ? Buffer.alloc(0) : Buffer.from(req.body);
  return new Uint8Array(Buffer.concat([head, body]));
}

export interface HttpResponse {
  readonly statusCode: number;
  readonly reasonPhrase: string;
  readonly httpVersion: string;
  readonly headers: readonly HeaderField[];
  readonly body: Uint8Array;
  /** True when the body hit `maxBodyBytes` and was truncated (the socket was then destroyed). */
  readonly truncated: boolean;
  /** Total bytes read off the socket (for the redacted completion audit). */
  readonly bytesRead: number;
}

export interface ReadOptions {
  /** Hard body ceiling (e.g. `engagement.max_response_body_bytes`, default 2 MiB). Oversize ⇒ truncate + destroy. */
  readonly maxBodyBytes: number;
  /** Header-section ceiling (default 64 KiB) — a response whose head exceeds this fails closed. */
  readonly maxHeaderBytes?: number;
  /** Idle timeout in ms; no data within the window fails closed. */
  readonly timeoutMs?: number;
  /** True when the request method was HEAD — the response carries no body regardless of its headers. */
  readonly headRequest?: boolean;
}

export type WireReason =
  | 'header_too_large'
  | 'malformed_status_line'
  | 'malformed_headers'
  | 'malformed_chunk'
  | 'connection_closed_early'
  | 'timeout';

/** A fixed-reason wire failure. Carries only the reason code — never response content. */
export class WireError extends Error {
  readonly reason: WireReason;
  constructor(reason: WireReason) {
    super(reason);
    this.name = 'WireError';
    this.reason = reason;
  }
}

interface ParsedHead {
  readonly statusCode: number;
  readonly reasonPhrase: string;
  readonly httpVersion: string;
  readonly headers: readonly HeaderField[];
  readonly contentLength: number | null;
  readonly chunked: boolean;
}

function parseHead(head: Buffer): ParsedHead | null {
  const text = head.toString('latin1');
  const lines = text.split(CRLF);
  const statusLine = lines[0] ?? '';
  const m = /^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/.exec(statusLine);
  if (m === null) return null;
  const headers: HeaderField[] = [];
  let contentLength: number | null = null;
  let chunked = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line === '') continue;
    const colon = line.indexOf(':');
    if (colon <= 0) return null;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers.push({ name, value });
    if (name === 'content-length') {
      if (!/^\d+$/.test(value)) return null;
      contentLength = Number(value);
    } else if (name === 'transfer-encoding' && /(^|,)\s*chunked\s*$/i.test(value)) {
      chunked = true;
    }
  }
  return {
    statusCode: Number(m[2]),
    reasonPhrase: m[3] ?? '',
    httpVersion: m[1] as string,
    headers,
    contentLength,
    chunked,
  };
}

/** A status that never carries a body (RFC 9110 §6.4.1): 1xx, 204, 304. */
function bodyless(status: number): boolean {
  return (status >= 100 && status < 200) || status === 204 || status === 304;
}

/**
 * Read one HTTP/1.1 response off the socket, bounded. Resolves with the parsed status/headers and a body capped at
 * `maxBodyBytes` (truncating + destroying the socket on overflow), or rejects with a fixed-reason `WireError`.
 */
export function readBoundedResponse(socket: Duplex, opts: ReadOptions): Promise<HttpResponse> {
  const maxHeaderBytes = opts.maxHeaderBytes ?? 65536;
  return new Promise<HttpResponse>((resolve, reject) => {
    let pending: Buffer = Buffer.alloc(0);
    let head: ParsedHead | null = null;
    let bytesRead = 0;
    let truncated = false;
    const bodyParts: Buffer[] = [];
    let bodyLen = 0;

    // Chunked-decoder state.
    let chunkNeed = -1; // bytes remaining in the current chunk's data (-1 ⇒ awaiting a size line)

    const finish = (): void => {
      cleanup();
      socket.destroy();
      resolve({
        statusCode: head!.statusCode,
        reasonPhrase: head!.reasonPhrase,
        httpVersion: head!.httpVersion,
        headers: head!.headers,
        body: new Uint8Array(Buffer.concat(bodyParts, bodyLen)),
        truncated,
        bytesRead,
      });
    };
    const fail = (reason: WireReason): void => {
      cleanup();
      socket.destroy();
      reject(new WireError(reason));
    };

    const pushBody = (buf: Buffer): boolean => {
      // Append up to the cap; returns true when the cap is reached (⇒ truncate + finish).
      const room = opts.maxBodyBytes - bodyLen;
      if (buf.length >= room) {
        if (room > 0) {
          bodyParts.push(buf.subarray(0, room));
          bodyLen += room;
        }
        truncated = true;
        return true;
      }
      bodyParts.push(buf);
      bodyLen += buf.length;
      return false;
    };

    // Returns true when the response is complete (or capped) and `finish()` should be called.
    const consumeChunked = (): boolean | WireReason => {
      for (;;) {
        if (chunkNeed === -1) {
          const nl = pending.indexOf('\r\n', 0, 'latin1');
          if (nl === -1) return maybeHeaderOverflow();
          const sizeTok = pending.subarray(0, nl).toString('latin1').split(';')[0]!.trim();
          if (!/^[0-9a-fA-F]+$/.test(sizeTok)) return 'malformed_chunk';
          const size = parseInt(sizeTok, 16);
          pending = pending.subarray(nl + 2);
          if (size === 0) return true; // last chunk; ignore any trailers, we cap here
          chunkNeed = size;
        }
        if (chunkNeed > 0) {
          const take = Math.min(chunkNeed, pending.length);
          if (take === 0) return false;
          if (pushBody(pending.subarray(0, take))) return true;
          pending = pending.subarray(take);
          chunkNeed -= take;
          if (chunkNeed > 0) return false;
        }
        // consume the trailing CRLF after the chunk data
        if (pending.length < 2) return false;
        if (pending.toString('latin1', 0, 2) !== CRLF) return 'malformed_chunk';
        pending = pending.subarray(2);
        chunkNeed = -1;
      }
    };

    const maybeHeaderOverflow = (): boolean => {
      // A pending buffer that never yields a chunk size line must still be bounded.
      if (pending.length > maxHeaderBytes) {
        truncated = true;
        return true;
      }
      return false;
    };

    const onData = (data: Buffer): void => {
      bytesRead += data.length;
      pending = pending.length === 0 ? data : Buffer.concat([pending, data]);

      if (head === null) {
        const sep = pending.indexOf('\r\n\r\n', 0, 'latin1');
        if (sep === -1) {
          if (pending.length > maxHeaderBytes) fail('header_too_large');
          return;
        }
        const parsed = parseHead(pending.subarray(0, sep));
        if (parsed === null) {
          fail(
            pending.subarray(0, sep).includes(0x0a) ? 'malformed_headers' : 'malformed_status_line',
          );
          return;
        }
        head = parsed;
        pending = pending.subarray(sep + 4);

        if (
          opts.headRequest === true ||
          bodyless(parsed.statusCode) ||
          parsed.contentLength === 0
        ) {
          finish();
          return;
        }
      }

      // Body phase.
      if (head.chunked) {
        const r = consumeChunked();
        if (r === true) finish();
        else if (typeof r === 'string') fail(r);
        return;
      }
      if (head.contentLength !== null) {
        const need = head.contentLength - bodyLen;
        const take = pending.subarray(0, Math.max(0, need));
        pending = Buffer.alloc(0);
        if (pushBody(take)) finish();
        else if (bodyLen >= head.contentLength) finish();
        return;
      }
      // Connection-close framing: keep the (capped) body; completion is signalled by 'end'.
      const rest = pending;
      pending = Buffer.alloc(0);
      if (pushBody(rest)) finish();
    };

    const onEnd = (): void => {
      if (head === null) {
        fail('connection_closed_early');
        return;
      }
      // For close-delimited (and lenient content-length) framings, end-of-stream completes the body.
      if (!head.chunked) finish();
      else fail('connection_closed_early');
    };
    /* v8 ignore next -- a mid-read TCP reset fails closed identically to an early close; not deterministically reproducible in CI. */
    const onError = (): void => fail('connection_closed_early');
    const onTimeout = (): void => fail('timeout');

    function cleanup(): void {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', onError);
      socket.off('timeout', onTimeout);
    }

    // `setTimeout` exists on net.Socket / tls.TLSSocket (the real transports) but not on the base Duplex type.
    const timed = socket as Duplex & { setTimeout?: (ms: number) => unknown };
    if (opts.timeoutMs !== undefined && typeof timed.setTimeout === 'function') {
      timed.setTimeout(opts.timeoutMs);
    }
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onError);
    socket.on('timeout', onTimeout);
  });
}
