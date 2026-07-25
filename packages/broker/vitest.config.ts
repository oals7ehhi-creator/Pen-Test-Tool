import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Resolve the workspace deps from SOURCE during tests so the suite does not depend on build order.
    alias: {
      '@pentest/scope': fileURLToPath(new URL('../scope/src/index.ts', import.meta.url)),
      '@pentest/spec': fileURLToPath(new URL('../spec/src/index.ts', import.meta.url)),
    },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // The Broker is the sole target-socket creator: hold its resolve/validate/pin/redirect core to the high bar.
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 90 },
    },
  },
});
