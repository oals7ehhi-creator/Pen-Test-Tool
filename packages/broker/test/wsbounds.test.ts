import { describe, it, expect } from 'vitest';
import {
  evaluateWsFrame,
  createWsGovernor,
  WsBoundsError,
  type WsCaps,
  type WsConnectionState,
} from '../src/index.js';

/**
 * WebSocket per-connection bounds (§8/§7.2, slice 5f). Proves the pure connection-budget governor: an established
 * connection is bounded by duration (ws_max_duration_s), message count (ws_max_messages), and per-message size
 * (ws_max_message_bytes); the FIRST breach terminates with a fixed reason. Pure, no I/O — the persisted interlocks are
 * proven elsewhere; this governor holds only one connection's in-memory budget.
 */

const OPENED = 1_000_000;
const caps = (maxDurationMs: number, maxMessages: number, maxMessageBytes: number): WsCaps => ({
  maxDurationMs,
  maxMessages,
  maxMessageBytes,
});
const st = (messagesSeen: number, openedAtMs = OPENED): WsConnectionState => ({
  openedAtMs,
  messagesSeen,
});

describe('evaluateWsFrame — the pure per-connection budget', () => {
  const C = caps(300_000, 3, 1024); // 300s, 3 messages, 1 KiB each

  it('ALLOWS a message within every cap and advances the message count', () => {
    expect(evaluateWsFrame(st(0), C, { bytes: 512 }, OPENED)).toEqual({
      allow: true,
      state: { openedAtMs: OPENED, messagesSeen: 1 },
    });
    // an interior message advances from N to N+1.
    expect(evaluateWsFrame(st(1), C, { bytes: 1024 }, OPENED + 10)).toEqual({
      allow: true,
      state: { openedAtMs: OPENED, messagesSeen: 2 },
    });
  });

  describe('duration cap', () => {
    it('ALLOWS right up to (just under) the lifetime', () => {
      expect(evaluateWsFrame(st(0), C, { bytes: 1 }, OPENED + 299_999).allow).toBe(true);
    });
    it('TERMINATES ws_duration_exceeded at exactly the cap and beyond (>=)', () => {
      expect(evaluateWsFrame(st(0), C, { bytes: 1 }, OPENED + 300_000)).toEqual({
        allow: false,
        reason: 'ws_duration_exceeded',
      });
      expect(evaluateWsFrame(st(0), C, { bytes: 1 }, OPENED + 500_000)).toEqual({
        allow: false,
        reason: 'ws_duration_exceeded',
      });
    });
  });

  describe('message-count cap', () => {
    it('ALLOWS exactly up to ws_max_messages, then TERMINATES the next one', () => {
      // the 3rd message (messagesSeen 2 -> 3) is admitted; the 4th (messagesSeen 3 -> would be 4) is refused.
      expect(evaluateWsFrame(st(2), C, { bytes: 1 }, OPENED).allow).toBe(true);
      expect(evaluateWsFrame(st(3), C, { bytes: 1 }, OPENED)).toEqual({
        allow: false,
        reason: 'ws_message_count_exceeded',
      });
    });
  });

  describe('message-size cap', () => {
    it('ALLOWS a message exactly at the byte cap and TERMINATES one over', () => {
      expect(evaluateWsFrame(st(0), C, { bytes: 1024 }, OPENED).allow).toBe(true);
      expect(evaluateWsFrame(st(0), C, { bytes: 1025 }, OPENED)).toEqual({
        allow: false,
        reason: 'ws_message_too_large',
      });
    });
  });

  describe('deterministic precedence when several caps breach at once', () => {
    it('DURATION wins over count and size', () => {
      expect(evaluateWsFrame(st(9), C, { bytes: 9999 }, OPENED + 300_000)).toEqual({
        allow: false,
        reason: 'ws_duration_exceeded',
      });
    });
    it('COUNT wins over size (within the lifetime)', () => {
      expect(evaluateWsFrame(st(3), C, { bytes: 9999 }, OPENED)).toEqual({
        allow: false,
        reason: 'ws_message_count_exceeded',
      });
    });
  });
});

describe('createWsGovernor — the stateful per-connection wrapper', () => {
  it('threads the budget across frames and exposes the running message count', () => {
    const g = createWsGovernor(caps(300_000, 5, 1024), OPENED);
    expect(g.messages).toBe(0);
    g.admit(100, OPENED + 1);
    g.admit(200, OPENED + 2);
    expect(g.messages).toBe(2);
  });

  it('THROWS a fixed-reason WsBoundsError on a size breach — and does not advance the count', () => {
    const g = createWsGovernor(caps(300_000, 5, 1024), OPENED);
    g.admit(1024, OPENED + 1); // ok
    expect(() => g.admit(2048, OPENED + 2)).toThrow(WsBoundsError);
    expect(g.messages).toBe(1); // the breaching frame was NOT counted
  });

  it('THROWS ws_message_count_exceeded once the message budget is spent', () => {
    const g = createWsGovernor(caps(300_000, 2, 1024), OPENED);
    g.admit(1, OPENED);
    g.admit(1, OPENED);
    expect(() => g.admit(1, OPENED)).toThrow(/ws_message_count_exceeded/);
  });

  it('THROWS ws_duration_exceeded once the lifetime elapses', () => {
    const g = createWsGovernor(caps(1_000, 100, 1024), OPENED);
    g.admit(1, OPENED + 500); // within the 1s lifetime
    expect(() => g.admit(1, OPENED + 1_000)).toThrow(/ws_duration_exceeded/);
    expect(g.messages).toBe(1);
  });

  it('the WsBoundsError message is exactly the fixed reason code (no leak)', () => {
    const err = new WsBoundsError('ws_message_too_large');
    expect(err).toBeInstanceOf(WsBoundsError);
    expect(err.message).toBe('ws_message_too_large');
    expect(err.reason).toBe('ws_message_too_large');
  });
});
