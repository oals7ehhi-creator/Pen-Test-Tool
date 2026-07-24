import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // The scope/SSRF guard is the network-safety chokepoint: hold it to a high bar.
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 90 },
    },
  },
});
