// Configuración ESLint (flat config) mínima para el CLI: reglas recomendadas de
// JavaScript y de @typescript-eslint sobre src/, test/ y bin/.
import js from '@eslint/js'
import tsParser from '@typescript-eslint/parser'
import tsPlugin from '@typescript-eslint/eslint-plugin'

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'oclif.manifest.json', 'coverage/**'],
  },
  js.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {ecmaVersion: 2022, sourceType: 'module'},
    },
    plugins: {'@typescript-eslint': tsPlugin},
    rules: {
      ...tsPlugin.configs.recommended.rules,
      // TypeScript comprueba los identificadores y los tipos; ESLint core da falsos positivos.
      'no-undef': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['error', {argsIgnorePattern: '^_', varsIgnorePattern: '^_'}],
    },
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {process: 'readonly', console: 'readonly'},
    },
  },
]
