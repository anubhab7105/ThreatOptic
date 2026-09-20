import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'vite.config.ts', '**/*.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        URL: 'readonly',
        Blob: 'readonly',
        FormData: 'readonly',
        confirm: 'readonly',
        AbortController: 'readonly',
        Event: 'readonly',
      },
    },
  },
  // Pragmatic any for untyped API payloads: warn, don't fail the gate.
  { rules: { '@typescript-eslint/no-explicit-any': 'warn' } },
);
