import { describe, it, expect } from 'vitest';
import net from 'node:net';
import { PassThrough, type Duplex } from 'node:stream';
import type { PeerCertificate } from 'node:tls';
import {
  buildTcpOptions,
  buildTlsOptions,
  connectPinned,
  nodeConnectors,
  type ConnectTarget,
  type Connectors,
} from '../src/index.js';

/**
 * Pinned-IP connect (§7.1 step 12). Proves the anti-rebinding socket contract: the broker dials the PINNED IP (never
 * the hostname → no second resolution), presents the CANONICAL HOST as SNI, and validates the certificate against the
 * canonical host — never the pinned IP. Option construction is unit-tested; a real loopback socket proves the pinned
 * IP is what actually gets dialed.
 */

const target = (over: Partial<ConnectTarget> = {}): ConnectTarget => ({
  host: 'example.com',
  port: 443,
  tls: true,
  ...over,
});

const FAKE_CERT = {} as PeerCertificate;

describe('buildTcpOptions / buildTlsOptions — the anti-rebinding contract', () => {
  it('dials the PINNED IP, not the hostname (no re-resolution)', () => {
    expect(buildTcpOptions('93.184.216.34', target({ tls: false, port: 80 }))).toEqual({
      host: '93.184.216.34',
      port: 80,
    });
    const t = buildTlsOptions('93.184.216.34', target());
    expect(t.host).toBe('93.184.216.34');
    expect(t.port).toBe(443);
  });

  it('presents the CANONICAL HOST as SNI', () => {
    expect(buildTlsOptions('93.184.216.34', target()).servername).toBe('example.com');
  });

  it('pins rejectUnauthorized=true in-code, so an env toggle cannot disable chain validation', () => {
    expect(buildTlsOptions('93.184.216.34', target()).rejectUnauthorized).toBe(true);
  });

  it('validates the certificate against the CANONICAL HOST — never the pinned IP or the name Node passes', () => {
    let checkedHost: string | undefined;
    const spy = (host: string): Error | undefined => {
      checkedHost = host;
      return undefined;
    };
    const opts = buildTlsOptions('93.184.216.34', target(), spy);
    // Node would hand checkServerIdentity the pinned IP / echoed SNI; ours ignores it and checks the canonical host.
    const result = opts.checkServerIdentity?.('93.184.216.34', FAKE_CERT);
    expect(checkedHost).toBe('example.com');
    expect(result).toBeUndefined();
  });

  it('surfaces a certificate-identity failure from the underlying checker', () => {
    const fail = (): Error => new Error('cert mismatch');
    const opts = buildTlsOptions('93.184.216.34', target(), fail);
    expect(opts.checkServerIdentity?.('x', FAKE_CERT)).toBeInstanceOf(Error);
  });
});

describe('connectPinned', () => {
  it('dispatches TLS vs plain TCP to the matching connector with pinned-IP options', () => {
    const calls: { kind: string; opts: Record<string, unknown> }[] = [];
    const fake: Connectors = {
      tcp: (o) => {
        calls.push({ kind: 'tcp', opts: o as unknown as Record<string, unknown> });
        return new PassThrough();
      },
      tls: (o) => {
        calls.push({ kind: 'tls', opts: o as unknown as Record<string, unknown> });
        return new PassThrough();
      },
    };
    connectPinned('10.0.0.9', target({ tls: false, port: 8080 }), fake);
    connectPinned('93.184.216.34', target(), fake);
    expect(calls[0]).toMatchObject({ kind: 'tcp', opts: { host: '10.0.0.9', port: 8080 } });
    expect(calls[1]).toMatchObject({
      kind: 'tls',
      opts: { host: '93.184.216.34', servername: 'example.com' },
    });
  });

  it('refuses a non-IP pinned host (structural anti-rebinding — never dials a name that could re-resolve)', () => {
    let dialed = false;
    const fake: Connectors = {
      tcp: () => {
        dialed = true;
        return new PassThrough();
      },
      tls: () => {
        dialed = true;
        return new PassThrough();
      },
    };
    expect(() => connectPinned('example.com', target({ tls: false }), fake)).toThrow(/IP literal/);
    expect(() => connectPinned('example.com', target(), fake)).toThrow(/IP literal/);
    expect(dialed).toBe(false); // never reached a connector
  });

  it('opens a REAL socket to the pinned IP and round-trips (plain TCP loopback)', async () => {
    // The canonical host is 'example.com' but we dial 127.0.0.1 — proving the PINNED IP is what gets connected.
    const server = net.createServer((sock) => sock.pipe(sock));
    const port = await listen(server);
    try {
      const sock = connectPinned('127.0.0.1', { host: 'example.com', port, tls: false });
      expect(await roundTrip(sock, 'ping')).toBe('ping');
    } finally {
      await close(server);
    }
  });

  it('uses the default node connectors — a refused pinned IP surfaces a socket error (tcp and tls)', async () => {
    const port = await refusedPort();
    for (const tlsFlag of [false, true]) {
      const sock = connectPinned(
        '127.0.0.1',
        { host: 'example.com', port, tls: tlsFlag },
        nodeConnectors,
      );
      const err = await new Promise<Error>((resolve) => sock.on('error', resolve));
      expect(err).toBeInstanceOf(Error);
      sock.destroy();
    }
  });
});

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port)),
  );
}

function close(server: net.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function roundTrip(sock: Duplex, msg: string): Promise<string> {
  return new Promise((resolve, reject) => {
    sock.on('error', reject);
    sock.once('data', (d: Buffer) => {
      resolve(d.toString('utf8'));
      sock.destroy();
    });
    sock.write(msg);
  });
}

/** A port that is bound then immediately closed, so a connect to it is refused. */
async function refusedPort(): Promise<number> {
  const s = net.createServer();
  const port = await listen(s);
  await close(s);
  return port;
}
