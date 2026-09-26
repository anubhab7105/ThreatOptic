import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// The repo root is the env dir, so the frontend reads the SAME single .env as
// the backend and docker-compose instead of a second hand-synced copy in
// frontend/.env. Only VITE_-prefixed keys are exposed to client code, so the
// server secrets living in that same file are not shipped to the browser.
const envDir = '..';

export default defineConfig(({ mode }) => {
  // Must come from loadEnv, not process.env: the latter only sees the real
  // process environment, so a VITE_PROXY_TARGET set in the .env file was
  // silently ignored and the default always won.
  const env = loadEnv(mode, envDir, '');
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8000';

  return {
    envDir,
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': { target: proxyTarget, changeOrigin: true },
        '/health': { target: proxyTarget, changeOrigin: true },
      },
    },
    preview: { port: 4173 },
    build: {
      sourcemap: false,
      chunkSizeWarningLimit: 600,
      cssCodeSplit: true,
      reportCompressedSize: true,
      modulePreload: { polyfill: false },
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              if (id.includes('react-router-dom')) return 'vendor-router';
              if (id.includes('react') || id.includes('react-dom'))
                return 'vendor-react';
              if (id.includes('@supabase')) return 'vendor-supabase';
              return 'vendor';
            }
          },
          chunkFileNames: 'assets/[name]-[hash].js',
          entryFileNames: 'assets/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash].[ext]',
        },
      },
    },
    esbuild: {
      drop: ['console', 'debugger'],
      legalComments: 'none',
    },
  };
});
