import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/dist-report/**',
      '**/coverage/**',
      'reports/**',
      'playwright-report/**',
      'test-results/**',
      'packages/cli/test/fixtures/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['*.js', '*.mjs', 'scripts/*.mjs', 'packages/*/scripts/*.mjs'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      eqeqeq: ['error', 'always'],
      'no-console': 'off',
    },
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['packages/cli/**/*.ts'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    // A snapshot from someone else is parsed with these schemas: every list
    // needs a limit and must stop at its first invalid element (SEC-21).
    files: ['packages/cli/src/model/**/*.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.object.name='z'][callee.property.name='array']",
          message:
            'Use list() from model/list.ts, which bounds the list and stops at its first invalid element.',
        },
        {
          selector: "CallExpression[callee.property.name='array'][arguments.length=0]",
          message:
            'Use list() from model/list.ts, which bounds the list and stops at its first invalid element.',
        },
      ],
    },
  },
  {
    files: ['packages/ui/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    languageOptions: { globals: { ...globals.browser } },
    rules: { ...reactHooks.configs['recommended-latest'].rules },
  },
);
