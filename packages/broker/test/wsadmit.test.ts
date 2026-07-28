import { describe, it, expect } from 'vitest';
import {
  evaluateWsAdmission,
  createWsAdmissionGate,
  WsConnectionLimitError,
  type WsAdmissionSnapshot,
  type WsAdmissionConfig,
  type WsSlotController,
  type WsSlotRef,
  type WsSlotReleaseRef,
  type WsSlotOutcome,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * WebSocket connection admission (§8/§7.2, slice 5g). Proves the pure admission decision (admit only strictly below
 * max_ws_connections; a cap of 0 disables WS) and the broker gate over an injected slot controller: it acquires for a
 * ws/wss handshake (fixed-reason fail-closed denial → no socket) and is a NO-OP for an HTTP request. The atomic
 * crash-safe lease read-modify-write is proven separately in db/test.
 */

const snap = (liveConnections: number): WsAdmissionSnapshot => ({ liveConnections });
const cfg = (maxWsConnections: number): WsAdmissionConfig => ({ maxWsConnections });

describe('evaluateWsAdmission — admit only below the connection cap', () => {
  it('ALLOWS when live connections are below the cap', () => {
    expect(evaluateWsAdmission(snap(0), cfg(1))).toEqual({ allow: true });
    expect(evaluateWsAdmission(snap(3), cfg(4))).toEqual({ allow: true });
  });

  it('DENIES ws_connection_limit exactly at the cap', () => {
    expect(evaluateWsAdmission(snap(4), cfg(4))).toEqual({
      allow: false,
      reason: 'ws_connection_limit',
    });
  });

  it('DENIES every connection when the cap is 0 (WebSockets disabled)', () => {
    expect(evaluateWsAdmission(snap(0), cfg(0))).toEqual({
      allow: false,
      reason: 'ws_connection_limit',
    });
  });
});

describe('createWsAdmissionGate', () => {
  const claims = { tenantId: 't1', engagementId: 'e1' };
  const wsRequest = { host: 'example.com', scheme: 'wss' } as unknown as ReconstructedRequest;
  const httpRequest = { host: 'example.com', scheme: 'https' } as unknown as ReconstructedRequest;

  const controllerOf = (
    behaviour: WsSlotOutcome | (() => Promise<never>),
  ): {
    controller: WsSlotController;
    acquired: WsSlotRef[];
    released: WsSlotReleaseRef[];
  } => {
    const acquired: WsSlotRef[] = [];
    const released: WsSlotReleaseRef[] = [];
    const controller: WsSlotController = {
      acquire: async (ref) => {
        acquired.push(ref);
        if (typeof behaviour === 'function') return behaviour();
        return behaviour;
      },
      release: async (ref) => {
        released.push(ref);
      },
    };
    return { controller, acquired, released };
  };

  it('acquires a connection slot for the engagement on a ws/wss handshake, passing on success', async () => {
    const { controller, acquired } = controllerOf({ ok: true, slotId: 's-1' });
    await expect(
      createWsAdmissionGate(controller)({ claims, request: wsRequest }),
    ).resolves.toBeUndefined();
    expect(acquired).toEqual([{ tenantId: 't1', engagementId: 'e1' }]);
  });

  it('is a NO-OP for an HTTP request — no slot is consumed', async () => {
    const { controller, acquired } = controllerOf({ ok: false, reason: 'ws_connection_limit' });
    await expect(
      createWsAdmissionGate(controller)({ claims, request: httpRequest }),
    ).resolves.toBeUndefined();
    expect(acquired).toEqual([]); // the gate never touched the controller for a non-WS request
  });

  it('DENY with the fixed reason (ws_connection_limit) — a WsConnectionLimitError, no socket downstream', async () => {
    const { controller } = controllerOf({ ok: false, reason: 'ws_connection_limit' });
    await expect(
      createWsAdmissionGate(controller)({ claims, request: wsRequest }),
    ).rejects.toBeInstanceOf(WsConnectionLimitError);
    await expect(createWsAdmissionGate(controller)({ claims, request: wsRequest })).rejects.toThrow(
      /ws_connection_limit/,
    );
  });

  it('fails closed when the controller throws', async () => {
    const { controller } = controllerOf(() => Promise.reject(new Error('db_down')));
    await expect(createWsAdmissionGate(controller)({ claims, request: wsRequest })).rejects.toThrow(
      /db_down/,
    );
  });

  it('the WsConnectionLimitError message is exactly the fixed reason code (no leak)', () => {
    const err = new WsConnectionLimitError('ws_connection_limit');
    expect(err).toBeInstanceOf(WsConnectionLimitError);
    expect(err.message).toBe('ws_connection_limit');
    expect(err.reason).toBe('ws_connection_limit');
  });
});
