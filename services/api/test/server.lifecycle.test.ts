import { describe, it, expect, afterEach } from 'vitest';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { AppConfig } from '@pentest/shared';
import { start } from '../src/server.js';
import { TEST_KEY_MATERIAL } from './factories.js';

/**
 * Server lifecycle proof: `start()` binds a real loopback socket, serves the public health route, and shuts
 * down cleanly. It boots on an EPHEMERAL signing key in a non-production environment (Compose stays usable), and
 * binds only to 127.0.0.1 (never a public interface).
 */

const cfg: AppConfig = {
  nodeEnv: 'development',
  apiHost: '127.0.0.1',
  apiPort: 0, // ephemeral port
  logLevel: 'error', // keep the boot log quiet; the api_listening call still executes
  databaseUrl: 'postgresql://u:p@127.0.0.1:5432/db',
  sessionSigningKeyRef: 'lifecycle-test-signing-key-ref',
  authIssuer: 'pentest-tool',
  authAudience: 'pentest-api',
  devTokenMinterEnabled: false,
};

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

function httpReq(
  port: number,
  path: string,
  method = 'GET',
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

function httpGet(port: number, path: string): Promise<{ status: number; body: string }> {
  return httpReq(port, path, 'GET');
}

describe('start() — real server lifecycle', () => {
  it('binds loopback, serves /healthz (200), and refuses a protected route without a session (401)', async () => {
    server = start(cfg);
    await new Promise<void>((resolve) => server!.once('listening', resolve));
    const addr = server.address() as AddressInfo;
    expect(addr.address).toBe('127.0.0.1'); // loopback only, never 0.0.0.0

    const health = await httpGet(addr.port, '/healthz');
    expect(health.status).toBe(200);
    expect(JSON.parse(health.body)).toEqual({ status: 'ok' });

    // Default-deny: a protected route with no verified session is 401 through the real socket.
    const audit = await httpGet(addr.port, '/audit');
    expect(audit.status).toBe(401);
  });

  it('in PRODUCTION the dev token minter is structurally unavailable (404) even if the config enables it', async () => {
    // A misconfigured production deployment that (wrongly) turns the minter on. It must STILL be a 404, and no
    // token may be minted, through the real socket. Production requires strong key material to boot, supplied via
    // env for this one boot and restored afterwards.
    const prev = process.env.SESSION_SIGNING_KEY_MATERIAL;
    process.env.SESSION_SIGNING_KEY_MATERIAL = TEST_KEY_MATERIAL;
    try {
      server = start({
        ...cfg,
        nodeEnv: 'production',
        devTokenMinterEnabled: true,
        sessionSigningKeyRef: 'prod-lifecycle-signing-key-ref',
      } as AppConfig);
      await new Promise<void>((resolve) => server!.once('listening', resolve));
      const addr = server.address() as AddressInfo;
      const minted = await httpReq(addr.port, '/dev/token', 'POST', {
        'x-dev-mint-role': 'administrator',
      });
      expect(minted.status).toBe(404);
      expect(minted.body).not.toContain('token');
    } finally {
      if (prev === undefined) delete process.env.SESSION_SIGNING_KEY_MATERIAL;
      else process.env.SESSION_SIGNING_KEY_MATERIAL = prev;
    }
  });
});
