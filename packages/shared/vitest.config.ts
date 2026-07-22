import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // The safety core is small and load-bearing: hold it to a high bar.
      thresholds: { statements: 85, branches: 80, functions: 85, lines: 85 },
    },
  },
});
