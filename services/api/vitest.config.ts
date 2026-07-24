import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Resolve the workspace dependency from SOURCE during tests so the suite does not depend on build order.
    alias: {
      '@pentest/shared': fileURLToPath(
        new URL('../../packages/shared/src/index.ts', import.meta.url),
      ),
    },
    coverage: {
      provider: 'v8',
      // Safety-critical API code (authentication, routing, default-deny authorization, allowlist logging) is
      // measured. Nothing here is broadly excluded — the only carve-out is the thin `if (import.meta.url …)`
      // process-bootstrap block in server.ts, ignored inline with a `/* v8 ignore */` marker (it cannot be
      // exercised through the in-process HTTP handler tests).
      include: ['src/**/*.ts'],
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 90 },
    },
  },
});
