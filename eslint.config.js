import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: ['vendor/**', 'node_modules/**', 'dist/**', '.cache/**', 'var/**'],
  },
  js.configs.recommended,
  {
    files: ['resources/assets/js/**/*.js', 'site/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-implicit-globals': 'error',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Use textContent; the CSP enforces Trusted Types.' },
        { property: 'outerHTML', message: 'Use DOM APIs; the CSP enforces Trusted Types.' },
      ],
    },
  },
  {
    files: ['tests/**/*.mjs', 'scripts/**/*.mjs', 'eslint.config.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'prefer-const': 'error',
    },
  },
];
