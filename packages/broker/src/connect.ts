/**
 * Pinned-IP connect (Phase 0 §7.1 step 12 / doc 10 §3 step 8). After `resolveAndPin` has guarded every resolved
 * address and pinned ONE validated IP, the broker dials that pinned IP — and ONLY it. This module encodes the
 * connect-time anti-rebinding contract as the exact socket options:
 *
 *   - the TCP connection is opened to the PINNED IP (never to the hostname → no second, unguarded resolution / TOCTOU);
 *   - for TLS the SNI is the CANONICAL HOST (so the server selects the right certificate), and the certificate identity
 *     is validated against the CANONICAL HOST — never against the pinned IP, and never against whatever name Node would
 *     otherwise default to. A cert that does not match the canonical host fails the handshake (SI-004).
 *
 * The socket factories are injected (default: `node:net` / `node:tls`) so the option-construction — the security
 * decision — is unit-tested in isolation, and a real loopback socket proves the pinned IP is what actually gets dialed.
 * This module returns the connecting socket; the request/response wire layer (send, size/time caps) is wired later.
 */

import net from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { parseIpLiteral } from '@pentest/scope';

/** Where to connect: the canonical host (SNI + cert identity bind HERE), the port, and whether TLS is used. */
export interface ConnectTarget {
  /** The spec's canonical host. SNI + certificate identity are validated against this, NEVER the pinned IP. */
  readonly host: string;
  readonly port: number;
  /** TLS for `https`/`wss`; plain TCP for `http`/`ws`. */
  readonly tls: boolean;
}

/** Injectable socket factories. Default binds to `node:net` / `node:tls`; tests substitute fakes. */
export interface Connectors {
  readonly tcp: (opts: net.TcpNetConnectOpts) => Duplex;
  readonly tls: (opts: tls.ConnectionOptions) => Duplex;
}

export const nodeConnectors: Connectors = {
  tcp: (opts) => net.connect(opts),
  tls: (opts) => tls.connect(opts),
};

/** Plain-TCP connect options: dial the PINNED IP on the target port. */
export function buildTcpOptions(pinnedIp: string, target: ConnectTarget): net.TcpNetConnectOpts {
  return { host: pinnedIp, port: target.port };
}

/**
 * TLS connect options: dial the PINNED IP, present the CANONICAL HOST as SNI, and validate the server certificate
 * against the CANONICAL HOST (not the pinned IP, not Node's default). `checkIdentity` is injectable for testing; it
 * defaults to Node's RFC 6125 `tls.checkServerIdentity`.
 */
export function buildTlsOptions(
  pinnedIp: string,
  target: ConnectTarget,
  checkIdentity: (
    host: string,
    cert: tls.PeerCertificate,
  ) => Error | undefined = tls.checkServerIdentity,
): tls.ConnectionOptions {
  return {
    host: pinnedIp,
    port: target.port,
    servername: target.host,
    // Enforce chain validation IN-CODE: an explicit `true` overrides NODE_TLS_REJECT_UNAUTHORIZED=0, so the cert
    // binding cannot be silently disabled by the runtime environment (SI-004 stays a technical control).
    rejectUnauthorized: true,
    // Ignore the name Node would pass (derived from host/servername) and always check against the canonical host.
    checkServerIdentity: (_hostname, cert) => checkIdentity(target.host, cert),
  };
}

/**
 * Open a connection to the pinned IP, honouring the anti-rebinding contract above. Returns the connecting socket
 * (the caller applies timeouts, sends the reconstructed request, and enforces size/time caps).
 */
export function connectPinned(
  pinnedIp: string,
  target: ConnectTarget,
  connectors: Connectors = nodeConnectors,
): Duplex {
  // Structural anti-rebinding guard: the dial host MUST be an IP literal, never a hostname — otherwise net/tls would
  // fall back to dns.lookup (consulting the OS hosts file), reintroducing the unguarded second resolution the pin
  // exists to prevent. resolveAndPin always yields a canonical IP; this enforces the contract rather than trusting it.
  if (parseIpLiteral(pinnedIp) === null) {
    throw new Error('connect: pinned host must be an IP literal');
  }
  return target.tls
    ? connectors.tls(buildTlsOptions(pinnedIp, target))
    : connectors.tcp(buildTcpOptions(pinnedIp, target));
}
