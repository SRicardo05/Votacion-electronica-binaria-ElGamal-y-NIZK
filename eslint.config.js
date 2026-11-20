// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

/**
 * Reglas de arquitectura: cada capa solo puede depender de las capas "inferiores".
 *
 *   crypto       → (nada del proyecto)          primitivas puras, sin E/S
 *   schema       → crypto                       formatos de mensaje versionados
 *   protocol     → crypto, schema               lógica de dominio + puertos (interfaces)
 *   persistence  → crypto, schema, protocol     adaptadores SQLite de los puertos
 *   api          → todo lo anterior             Express (raíz de composición del servidor)
 *   client       → crypto, schema               cliente de votación (nunca ve claves de la autoridad)
 *   verifier     → crypto, schema               auditor independiente, sin red ni BD
 */
const layer = (name) => `(^|/)${name}(/|$)`;

/** @param {string[]} layers @param {string[]} [pkgs] */
const forbid = (layers, pkgs = []) => ({
  'no-restricted-imports': [
    'error',
    {
      paths: pkgs.map((name) => ({ name, message: 'Dependencia no permitida en esta capa.' })),
      patterns: layers.map((l) => ({
        regex: layer(l),
        message: `Violación de arquitectura: esta capa no puede importar '${l}'.`,
      })),
    },
  ],
});

const IO_PKGS = ['express', 'better-sqlite3', 'node:fs', 'fs', 'node:http', 'http'];

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      // Prefijo "_" = ignorado a propósito (p. ej. el 4.º parámetro del manejador de errores de Express).
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', destructuredArrayIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['src/crypto/**/*.ts'],
    rules: forbid(['schema', 'protocol', 'persistence', 'api', 'client', 'verifier'], [...IO_PKGS, 'zod']),
  },
  {
    files: ['src/schema/**/*.ts'],
    rules: forbid(['protocol', 'persistence', 'api', 'client', 'verifier'], IO_PKGS),
  },
  {
    files: ['src/protocol/**/*.ts'],
    rules: forbid(['persistence', 'api', 'client', 'verifier'], IO_PKGS),
  },
  {
    files: ['src/persistence/**/*.ts'],
    rules: forbid(['api', 'client', 'verifier'], ['express']),
  },
  {
    files: ['src/client/**/*.ts'],
    rules: forbid(['protocol', 'persistence', 'api', 'verifier'], ['express', 'better-sqlite3']),
  },
  {
    files: ['src/verifier/**/*.ts'],
    rules: forbid(['protocol', 'persistence', 'api', 'client'], ['express', 'better-sqlite3', 'node:http', 'http']),
  },
  {
    files: ['*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
);
