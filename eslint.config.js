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
      // Command-injection baseline (Phase 1 no-shell gate): forbid STATIC imports of child_process.
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
      // no-restricted-imports only covers STATIC imports. Close the DYNAMIC bypasses too, so the no-shell gate
      // cannot be sidestepped with a dynamic import of the child_process module, a runtime require of it, or a
      // create-require alias. These selectors are the AST-level complement to the static rule above.
      'no-restricted-syntax': [
        'error',
        {
          selector: 'ImportExpression[source.value=/^(node:)?child_process$/]',
          message: 'No dynamic import of child_process (Phase 1 no-shell safety gate).',
        },
        {
          selector:
            "CallExpression[callee.name='require'][arguments.0.value=/^(node:)?child_process$/]",
          message: 'No require() of child_process (Phase 1 no-shell safety gate).',
        },
        {
          selector: "CallExpression[callee.name='createRequire']",
          message:
            'No createRequire — an indirect-require escape hatch around the no-shell safety gate (Phase 1).',
        },
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
    },
  },
);
