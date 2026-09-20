import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'vite.config.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  // Pragmatic any for untyped API payloads: warn, don't fail the gate.
  { rules: { '@typescript-eslint/no-explicit-any': 'warn' } },
);
