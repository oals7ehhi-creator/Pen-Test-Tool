import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  selectWsFrame,
  createWsFrameEmitter,
  WsFrameError,
  type WsFrameSet,
  type WsFrameTemplate,
  type WsFrameContext,
} from '../src/index.js';

/**
 * WebSocket outbound frame-set restriction (§7.2 / SI-063, slice 5h). Proves that an outbound frame can ONLY be an
 * entry of the approved, content-addressed `ws_frame_set` catalog: the emitter takes a catalog NAME and returns THAT
 * entry's bytes, so a non-catalog frame is structurally unrepresentable (not merely filtered). Every ambiguity or
 * malformation fails closed with a fixed reason. Pure + injected fetch — no egress, no socket.
 */

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');
const frame = (over: Partial<WsFrameTemplate> = {}): WsFrameTemplate => ({
  name: 'ping-probe',
  opcode: 'text',
  dataBase64: b64('hello'),
  ...over,
});
const setOf = (...frames: WsFrameTemplate[]): WsFrameSet => ({ frames });
const utf8 = (u: Uint8Array): string => Buffer.from(u).toString('utf8');

describe('selectWsFrame — only an approved catalog entry may be emitted', () => {
  it('ALLOWS a named entry and returns the CATALOG bytes (decoded from the approved set)', () => {
    const s = setOf(frame(), frame({ name: 'other', dataBase64: b64('world') }));
    const sel = selectWsFrame(s, 'ping-probe');
    expect(sel.allow).toBe(true);
    if (sel.allow) {
      expect(sel.frame.name).toBe('ping-probe');
      expect(sel.frame.opcode).toBe('text');
      expect(utf8(sel.frame.data)).toBe('hello');
    }
  });

  it('carries arbitrary octets faithfully through base64 (binary frames are byte-exact)', () => {
    const bytes = Uint8Array.from([0x00, 0x01, 0xff, 0x7f, 0x80]);
    const s = setOf(
      frame({ name: 'bin', opcode: 'binary', dataBase64: Buffer.from(bytes).toString('base64') }),
    );
    const sel = selectWsFrame(s, 'bin');
    expect(sel.allow).toBe(true);
    if (sel.allow) {
      expect(sel.frame.opcode).toBe('binary');
      expect(Array.from(sel.frame.data)).toEqual([0x00, 0x01, 0xff, 0x7f, 0x80]);
    }
  });

  it('REFUSES a name absent from the catalog (the core SI-063 restriction)', () => {
    expect(selectWsFrame(setOf(frame()), 'not-approved')).toEqual({
      allow: false,
      reason: 'ws_frame_not_in_catalog',
    });
  });

  it('REFUSES every emission from an EMPTY approved set', () => {
    expect(selectWsFrame(setOf(), 'anything')).toEqual({
      allow: false,
      reason: 'ws_frame_set_empty',
    });
  });

  it('REFUSES a DUPLICATE name as ambiguous — neither candidate is emitted', () => {
    const s = setOf(frame({ dataBase64: b64('first') }), frame({ dataBase64: b64('second') }));
    expect(selectWsFrame(s, 'ping-probe')).toEqual({
      allow: false,
      reason: 'ws_frame_name_ambiguous',
    });
  });

  it('REFUSES an entry whose opcode is not a known DATA opcode (control frames are protocol-level)', () => {
    const bad = {
      name: 'ctl',
      opcode: 'close',
      dataBase64: b64('x'),
    } as unknown as WsFrameTemplate;
    expect(selectWsFrame(setOf(bad), 'ctl')).toEqual({
      allow: false,
      reason: 'ws_frame_opcode_invalid',
    });
  });
});

describe('createWsFrameEmitter — bound to the spec ws_frame_set_digest', () => {
  const ctxOf = (set: WsFrameSet | null): { ctx: WsFrameContext; asked: string[] } => {
    const asked: string[] = [];
    const ctx: WsFrameContext = {
      fetchWsFrameSet: async (digest) => {
        asked.push(digest);
        return set;
      },
    };
    return { ctx, asked };
  };

  it('fetches the approved set BY the spec digest and emits its entries', async () => {
    const { ctx, asked } = ctxOf(setOf(frame(), frame({ name: 'b', dataBase64: b64('bee') })));
    const emitter = await createWsFrameEmitter('a'.repeat(64), ctx);
    expect(asked).toEqual(['a'.repeat(64)]); // looked up by content digest, nothing else
    expect(utf8(emitter.emit('b').data)).toBe('bee');
    expect(emitter.approvedNames).toEqual(['ping-probe', 'b']);
  });

  it('fails CLOSED when the spec names no frame set (unbound)', async () => {
    const { ctx, asked } = ctxOf(setOf(frame()));
    await expect(createWsFrameEmitter(null, ctx)).rejects.toThrow(/ws_frame_set_unbound/);
    await expect(createWsFrameEmitter('', ctx)).rejects.toThrow(/ws_frame_set_unbound/);
    expect(asked).toEqual([]); // never even consulted the catalog
  });

  it('fails CLOSED when the digest resolves to nothing', async () => {
    const { ctx } = ctxOf(null);
    await expect(createWsFrameEmitter('b'.repeat(64), ctx)).rejects.toBeInstanceOf(WsFrameError);
    await expect(createWsFrameEmitter('b'.repeat(64), ctx)).rejects.toThrow(
      /ws_frame_set_not_found/,
    );
  });

  it('THROWS a fixed-reason WsFrameError when emitting a non-catalog frame — nothing goes on the wire', async () => {
    const { ctx } = ctxOf(setOf(frame()));
    const emitter = await createWsFrameEmitter('c'.repeat(64), ctx);
    let caught: unknown;
    try {
      emitter.emit('destructive-fuzz');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(WsFrameError);
    expect((caught as WsFrameError).reason).toBe('ws_frame_not_in_catalog');
    expect((caught as WsFrameError).message).toBe('ws_frame_not_in_catalog'); // exact — no name/bytes leak
  });

  it('STRUCTURAL: the emitted bytes always come from the catalog — a caller cannot supply frame content', async () => {
    // the only caller-controlled input is a NAME; there is no parameter through which bytes could be injected, so the
    // emitted payload is always exactly the approved entry's (SI-063: the broker cannot emit a frame outside the set).
    const { ctx } = ctxOf(setOf(frame({ name: 'safe', dataBase64: b64('approved-body') })));
    const emitter = await createWsFrameEmitter('d'.repeat(64), ctx);
    expect(utf8(emitter.emit('safe').data)).toBe('approved-body');
    // a name that LOOKS like frame content is still just a lookup key — it is not emitted, it is refused.
    expect(() => emitter.emit('{"op":"DROP TABLE"}')).toThrow(/ws_frame_not_in_catalog/);
  });

  it('the WsFrameError message is exactly the fixed reason code (no leak)', () => {
    const err = new WsFrameError('ws_frame_set_not_found');
    expect(err).toBeInstanceOf(WsFrameError);
    expect(err.message).toBe('ws_frame_set_not_found');
    expect(err.reason).toBe('ws_frame_set_not_found');
  });
});
