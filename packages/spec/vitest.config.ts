import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // request_spec content-addressing + the JIT egress grant are the integrity chokepoint of the two-stage
      // flow: hold them to the same high bar as the scope guard.
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 90 },
    },
  },
});
