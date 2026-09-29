import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'vite.config.ts', '**/*.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
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
        localStorage: 'readonly',
      },
    },
  },

  { rules: { '@typescript-eslint/no-explicit-any': 'warn' } },

  { rules: { 'react-hooks/set-state-in-effect': 'warn' } },
);
