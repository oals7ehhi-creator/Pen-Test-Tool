/**
 * WebSocket outbound frame-set restriction (Phase 0 doc 04 §7.2 / SI-063, slice 5h). Outbound frames on an established
 * WebSocket are drawn **ONLY** from the approved, content-addressed inert frame set named by the spec's
 * `ws_frame_set_digest` (a `ws_frame_set` `catalog_template`): "the broker CANNOT emit a frame outside that set …
 * never destructive fuzzing" (SI-063).
 *
 * The guarantee here is STRUCTURAL, not a filter. The emitter's `emit` names a curated catalog entry and returns THAT
 * entry's bytes — a caller never supplies frame bytes, so a non-catalog frame is not merely refused, it is
 * unrepresentable. This mirrors `reconstructRequest` (SI-061), which takes the payload bytes from the content-addressed
 * catalog rather than from a worker-serialized request.
 *
 * As in `reconstruct.ts`, the catalog is looked up BY its content digest: the store (migration `0003`) content-addresses
 * and trigger-verifies templates at write and rejects UPDATE/DELETE, so the broker does not re-derive the DB's
 * `jsonb::text` digest here (that cross-engine canonical-JSON is deliberately avoided). All I/O is INJECTED; this module
 * performs no egress and opens no socket.
 *
 * COMPOSITION — one enforcement point each, deliberately not duplicated:
 *   - SOURCE of a frame (this module): only an approved catalog entry may be emitted;
 *   - SIZE / COUNT / DURATION of frames (slice 5f, `wsbounds.ts`): the selected frame is then admitted (or the
 *     connection terminated) by the per-connection governor against `ws_max_message_bytes` / `ws_max_messages` /
 *     `ws_max_duration_s`;
 *   - ADMISSION of the connection itself (slice 5g, `wsadmit.ts`): `ws_in_flight <= max_ws_connections`.
 * The approval-manifest path by which a NON-catalog frame could ever be sent (§7.2) belongs to the approval-policy /
 * dual-control slice; until it exists, a non-catalog frame is simply unsendable — the fail-closed default.
 */

import { Buffer } from 'node:buffer';

/** The WebSocket DATA frame opcodes a curated catalog may carry. Control frames (ping/pong/close) are protocol-level —
 * the broker's wire path owns them and they are never drawn from the content catalog. */
export type WsFrameOpcode = 'text' | 'binary';

const WS_FRAME_OPCODES: ReadonlySet<string> = new Set<WsFrameOpcode>(['text', 'binary']);

/** Why an outbound frame was refused — a fixed code (never frame bytes / catalog content). */
export type WsFrameReason =
  | 'ws_frame_set_unbound'
  | 'ws_frame_set_not_found'
  | 'ws_frame_set_empty'
  | 'ws_frame_name_ambiguous'
  | 'ws_frame_opcode_invalid'
  | 'ws_frame_not_in_catalog';

/** A fixed-reason outbound-frame denial. Carries only the reason code — never frame bytes / names / peer detail. */
export class WsFrameError extends Error {
  readonly reason: WsFrameReason;
  constructor(reason: WsFrameReason) {
    super(reason); // the message IS the fixed reason code
    this.name = 'WsFrameError';
    this.reason = reason;
  }
}

/** One approved, inert outbound frame in the curated set. `dataBase64` so any octet is representable (as `Payload`). */
export interface WsFrameTemplate {
  /** The curated entry name — how the caller NAMES the frame to emit (stable, unlike a positional index). */
  readonly name: string;
  readonly opcode: WsFrameOpcode;
  /** The frame's inert payload bytes, base64-encoded. */
  readonly dataBase64: string;
}

/** The approved outbound frame set (a `ws_frame_set` catalog_template body). */
export interface WsFrameSet {
  readonly frames: readonly WsFrameTemplate[];
}

/** The exact frame the broker will put on the wire — bytes decoded FROM the catalog entry, never from a caller. */
export interface ApprovedWsFrame {
  readonly name: string;
  readonly opcode: WsFrameOpcode;
  readonly data: Uint8Array;
}

export type WsFrameSelection =
  | { readonly allow: true; readonly frame: ApprovedWsFrame }
  | { readonly allow: false; readonly reason: WsFrameReason };

/**
 * Select the named entry from the approved frame set (pure). Fails CLOSED on every ambiguity or malformation rather
 * than emitting anything: an EMPTY set admits no frame at all; a DUPLICATE name is ambiguous (mirroring
 * `query_path_ambiguous` in reconstruction) so neither candidate is emitted; an entry whose opcode is not a known DATA
 * opcode is refused; and a name absent from the set is refused. On allow, the returned bytes are decoded from the
 * CATALOG entry — the caller supplies only the name.
 */
export function selectWsFrame(set: WsFrameSet, name: string): WsFrameSelection {
  if (set.frames.length === 0) return { allow: false, reason: 'ws_frame_set_empty' };

  const matches = set.frames.filter((f) => f.name === name);
  if (matches.length > 1) return { allow: false, reason: 'ws_frame_name_ambiguous' };
  const entry = matches[0];
  if (entry === undefined) return { allow: false, reason: 'ws_frame_not_in_catalog' };
  if (!WS_FRAME_OPCODES.has(entry.opcode)) {
    return { allow: false, reason: 'ws_frame_opcode_invalid' };
  }

  return {
    allow: true,
    frame: {
      name: entry.name,
      opcode: entry.opcode,
      data: new Uint8Array(Buffer.from(entry.dataBase64, 'base64')),
    },
  };
}

/** The injected content-addressed catalog fetch for the `ws_frame_set` body (as `fetchPayload` in reconstruction). */
export interface WsFrameContext {
  readonly fetchWsFrameSet: (digest: string) => Promise<WsFrameSet | null>;
}

/**
 * The per-connection outbound-frame emitter. `emit` is the ONLY way to produce an outbound frame, and it takes a
 * catalog entry NAME — so the bytes always come from the approved set and a non-catalog frame is unrepresentable.
 */
export interface WsFrameEmitter {
  /** Emit the named approved frame, or THROW a fixed-reason `WsFrameError` (the caller sends nothing on a throw). */
  emit(name: string): ApprovedWsFrame;
  /** The names the approved set admits — for operator display / audit, never the frame bytes. */
  readonly approvedNames: readonly string[];
}

/**
 * Build the outbound-frame emitter for a `kind='websocket'` spec: fetch the approved set BY the spec's
 * `ws_frame_set_digest` and bind it to this connection. Fails CLOSED before any frame can be emitted when the spec
 * names no frame set (`ws_frame_set_unbound` — the DB's `ws_needs_frames` CHECK already requires one for a websocket
 * spec, so this is the broker-side defense in depth) or when the digest resolves to nothing
 * (`ws_frame_set_not_found`).
 */
export async function createWsFrameEmitter(
  wsFrameSetDigest: string | null,
  ctx: WsFrameContext,
): Promise<WsFrameEmitter> {
  if (wsFrameSetDigest === null || wsFrameSetDigest === '') {
    throw new WsFrameError('ws_frame_set_unbound');
  }
  const set = await ctx.fetchWsFrameSet(wsFrameSetDigest);
  if (set === null) throw new WsFrameError('ws_frame_set_not_found');

  return {
    emit(name: string): ApprovedWsFrame {
      const selection = selectWsFrame(set, name);
      if (!selection.allow) throw new WsFrameError(selection.reason);
      return selection.frame;
    },
    get approvedNames(): readonly string[] {
      return set.frames.map((f) => f.name);
    },
  };
}
