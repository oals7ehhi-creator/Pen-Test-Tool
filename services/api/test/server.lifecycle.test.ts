import { describe, it, expect, afterEach } from 'vitest';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { AppConfig } from '@pentest/shared';
import { start } from '../src/server.js';

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

function httpGet(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
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
});
