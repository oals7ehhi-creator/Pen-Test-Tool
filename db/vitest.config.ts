import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Every DB test file resets the SAME database (DROP SCHEMA public), so files must run one at a time —
    // otherwise two files racing on the shared Postgres would clobber each other's fixtures.
    fileParallelism: false,
    // Resolve the workspace dependency from SOURCE during tests so the suite does not depend on build order.
    alias: {
      '@pentest/shared': fileURLToPath(new URL('../packages/shared/src/index.ts', import.meta.url)),
    },
  },
});
