import { describe, it, expect } from 'vitest';
import net from 'node:net';
import { Buffer } from 'node:buffer';
import {
  serializeRequest,
  readBoundedResponse,
  WireError,
  type ReconstructedRequest,
  type ReadOptions,
} from '../src/index.js';

/**
 * Send/read wire (§7.1 step 12 SEND + §8 max_response_body_bytes). Proves the broker frames EXACTLY the reconstructed
 * request, and reads the response under a hard body cap: an oversize body is truncated (flagged) and the socket
 * destroyed — never fully buffered. Content-Length, chunked, and connection-close framings are all capped identically;
 * malformed / early-closed / slow responses fail closed with a fixed reason code.
 */

const req = (over: Partial<ReconstructedRequest> = {}): ReconstructedRequest => ({
  method: 'GET',
  scheme: 'https',
  host: 'example.com',
  port: 443,
  path: '/api',
  query: '',
  targetUrl: 'https://example.com/api',
  headers: [
    { name: 'host', value: 'example.com' },
    { name: 'accept', value: '*/*' },
  ],
  body: null,
  ...over,
});

describe('serializeRequest', () => {
  it('frames a GET as exact HTTP/1.1 origin-form bytes', () => {
    const bytes = Buffer.from(serializeRequest(req()));
    expect(bytes.toString('utf8')).toBe(
      'GET /api HTTP/1.1\r\nhost: example.com\r\naccept: */*\r\n\r\n',
    );
  });

  it('includes the query in the request-target and appends the body', () => {
    const bytes = Buffer.from(
      serializeRequest(
        req({
          method: 'POST',
          path: '/s',
          query: 'q=1&r=2',
          headers: [
            { name: 'host', value: 'example.com' },
            { name: 'content-length', value: '3' },
          ],
          body: new Uint8Array([0x61, 0x62, 0x63]),
        }),
      ),
    );
    expect(bytes.toString('utf8')).toBe(
      'POST /s?q=1&r=2 HTTP/1.1\r\nhost: example.com\r\ncontent-length: 3\r\n\r\nabc',
    );
  });
});

/** A loopback server that writes a fixed raw response to each connection (optionally leaving the socket open). */
function serveRaw(bytes: Buffer, close = true): Promise<{ port: number; server: net.Server }> {
  const server = net.createServer((sock) => {
    sock.write(bytes);
    if (close) sock.end();
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ port: (server.address() as net.AddressInfo).port, server }),
    ),
  );
}

async function readFrom(
  raw: string | Buffer,
  opts: ReadOptions,
  close = true,
): Promise<ReturnType<typeof readBoundedResponse> extends Promise<infer T> ? T : never> {
  const { port, server } = await serveRaw(Buffer.from(raw), close);
  try {
    const sock = net.connect(port, '127.0.0.1');
    return await readBoundedResponse(sock, opts);
  } finally {
    server.close();
  }
}

describe('readBoundedResponse — framing', () => {
  it('reads a Content-Length body', async () => {
    const res = await readFrom('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello', {
      maxBodyBytes: 1024,
    });
    expect(res.statusCode).toBe(200);
    expect(res.reasonPhrase).toBe('OK');
    expect(Buffer.from(res.body).toString('utf8')).toBe('hello');
    expect(res.truncated).toBe(false);
    expect(res.headers).toContainEqual({ name: 'content-length', value: '5' });
  });

  it('decodes a chunked body', async () => {
    const res = await readFrom(
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n',
      { maxBodyBytes: 1024 },
    );
    expect(Buffer.from(res.body).toString('utf8')).toBe('Wikipedia');
    expect(res.truncated).toBe(false);
  });

  it('reassembles a chunked response delivered in fragments (partial chunks across packets)', async () => {
    // Real sockets split packets anywhere — including mid-chunk and mid-size-line. The reader must reassemble.
    const parts = [
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
      '4\r\nWi',
      'ki\r\n5\r\nped',
      'ia\r\n0\r\n\r\n',
    ];
    const server = net.createServer((sock) => {
      let i = 0;
      const pump = (): void => {
        if (i < parts.length) {
          sock.write(parts[i] as string);
          i++;
          setTimeout(pump, 10);
        } else {
          sock.end();
        }
      };
      pump();
    });
    const port = await new Promise<number>((resolve) =>
      server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port)),
    );
    try {
      const sock = net.connect(port, '127.0.0.1');
      const res = await readBoundedResponse(sock, { maxBodyBytes: 1024 });
      expect(Buffer.from(res.body).toString('utf8')).toBe('Wikipedia');
      expect(res.truncated).toBe(false);
    } finally {
      server.close();
    }
  });

  it('reads a connection-close-delimited body (no Content-Length)', async () => {
    const res = await readFrom('HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nsome body bytes', {
      maxBodyBytes: 1024,
    });
    expect(Buffer.from(res.body).toString('utf8')).toBe('some body bytes');
  });

  it('treats 204 as bodyless even if a body follows', async () => {
    const res = await readFrom('HTTP/1.1 204 No Content\r\n\r\n', { maxBodyBytes: 1024 });
    expect(res.statusCode).toBe(204);
    expect(res.body.length).toBe(0);
  });

  it('treats a HEAD response as bodyless despite a Content-Length', async () => {
    const res = await readFrom('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello', {
      maxBodyBytes: 1024,
      headRequest: true,
    });
    expect(res.body.length).toBe(0);
  });
});

describe('readBoundedResponse — the body cap (§8, never fully buffered)', () => {
  it('truncates an oversize Content-Length body and flags it', async () => {
    const res = await readFrom('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello', {
      maxBodyBytes: 3,
    });
    expect(Buffer.from(res.body).toString('utf8')).toBe('hel');
    expect(res.truncated).toBe(true);
  });

  it('truncates an oversize chunked body and flags it', async () => {
    const res = await readFrom(
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n',
      { maxBodyBytes: 5 },
    );
    expect(Buffer.from(res.body).toString('utf8')).toBe('Wikip');
    expect(res.truncated).toBe(true);
  });

  it('truncates an oversize connection-close body', async () => {
    const res = await readFrom('HTTP/1.1 200 OK\r\n\r\n0123456789', { maxBodyBytes: 4 });
    expect(Buffer.from(res.body).toString('utf8')).toBe('0123');
    expect(res.truncated).toBe(true);
  });

  it('bounds a chunked size-line that never terminates (defensive truncate)', async () => {
    const res = await readFrom(
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + '1'.repeat(100),
      { maxBodyBytes: 1024, maxHeaderBytes: 20 },
    );
    expect(res.truncated).toBe(true);
    expect(res.body.length).toBe(0);
  });
});

describe('readBoundedResponse — fails closed', () => {
  it('rejects a malformed status line', async () => {
    await expect(readFrom('NOT-HTTP\r\n\r\n', { maxBodyBytes: 16 })).rejects.toMatchObject({
      reason: 'malformed_status_line',
    });
  });

  it('rejects a malformed header line', async () => {
    await expect(
      readFrom('HTTP/1.1 200 OK\r\nbad-header-no-colon\r\n\r\n', { maxBodyBytes: 16 }),
    ).rejects.toBeInstanceOf(WireError);
  });

  it('rejects a non-numeric Content-Length', async () => {
    await expect(
      readFrom('HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n', { maxBodyBytes: 16 }),
    ).rejects.toBeInstanceOf(WireError);
  });

  it('rejects a malformed chunk size', async () => {
    await expect(
      readFrom('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n', {
        maxBodyBytes: 16,
      }),
    ).rejects.toMatchObject({ reason: 'malformed_chunk' });
  });

  it('rejects a header section that exceeds maxHeaderBytes', async () => {
    const longHead = 'HTTP/1.1 200 OK\r\nX-Long: ' + 'a'.repeat(200);
    await expect(
      readFrom(longHead, { maxBodyBytes: 16, maxHeaderBytes: 50 }, false),
    ).rejects.toMatchObject({ reason: 'header_too_large' });
  });

  it('rejects a connection closed before any headers arrived', async () => {
    await expect(readFrom('', { maxBodyBytes: 16 })).rejects.toMatchObject({
      reason: 'connection_closed_early',
    });
  });

  it('rejects a chunked stream closed before the terminal chunk', async () => {
    await expect(
      readFrom('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n', {
        maxBodyBytes: 1024,
      }),
    ).rejects.toMatchObject({ reason: 'connection_closed_early' });
  });

  it('times out a response that never arrives', async () => {
    const server = net.createServer(() => {
      /* accept but never write, never close */
    });
    const port = await new Promise<number>((resolve) =>
      server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port)),
    );
    try {
      const sock = net.connect(port, '127.0.0.1');
      await expect(
        readBoundedResponse(sock, { maxBodyBytes: 16, timeoutMs: 100 }),
      ).rejects.toMatchObject({ reason: 'timeout' });
    } finally {
      server.close();
    }
  });
});
