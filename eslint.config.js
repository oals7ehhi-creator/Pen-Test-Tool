// Flat ESLint config (ESLint 9). Type-aware linting across the workspace.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/build/**', '**/coverage/**', '**/node_modules/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // Node runtime globals for all source (services, scripts, config, tests run under Node).
    languageOptions: {
      globals: { ...globals.node },
    },
  },
  {
    rules: {
      // Command-injection baseline (Phase 1 no-shell gate): forbid child_process at the lint layer.
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'child_process',
              message: 'No shell/subprocess execution (Phase 1 no-shell safety gate).',
            },
            {
              name: 'node:child_process',
              message: 'No shell/subprocess execution (Phase 1 no-shell safety gate).',
            },
          ],
        },
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
    },
  },
);
