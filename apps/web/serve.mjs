// Phase 1 web placeholder server. Serves the static shell produced by build.mjs and exposes /healthz for the
// container health check. Dependency-free (Node stdlib) to match the rest of the Phase 1 foundation; a real
// frontend server replaces it later. Host exposure is loopback-only, enforced by docker-compose port mapping.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const host = process.env.WEB_HOST ?? '127.0.0.1';
const port = Number(process.env.WEB_PORT ?? 8080);
const indexPath = fileURLToPath(new URL('./dist/index.html', import.meta.url));

const server = createServer((req, res) => {
  const path = (req.url ?? '/').split('?')[0];
  if (path === '/healthz') {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end('{"status":"ok"}');
    return;
  }
  readFile(indexPath).then(
    (html) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(html);
    },
    () => {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.end('{"error":"build_missing"}');
    },
  );
});

server.listen(port, host, () => process.stdout.write(`web: serving on http://${host}:${port}\n`));
