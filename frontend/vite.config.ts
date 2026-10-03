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
    resolve: {
      // Single copy of React everywhere (fiber brings nested peer deps).
      dedupe: ['react', 'react-dom'],
    },
    server: {
      port: 5173,
      proxy: {
        '/api': { target: proxyTarget, changeOrigin: true, ws: true },
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
              // React-free 3D engines only. These are imported exclusively via
              // lazy 3D scenes, so the chunks load after first paint.
              // NOTE: never match a loose 'three' substring — it also catches
              // '@react-three/fiber', which must stay in the main module graph
              // with React (splitting them caused a vendor<->vendor-react
              // cycle and a blank-page useLayoutEffect crash).
              const norm = id.replace(/\\/g, '/');
              if (norm.includes('node_modules/three/')) return 'vendor-three';
              if (norm.includes('node_modules/maath/')) return 'vendor-three';
              if (norm.includes('node_modules/cobe/')) return 'vendor-cobe';
              // Fiber and its React-side helpers are imported ONLY by the lazy
              // hero scene. Return undefined so Rollup keeps them in that async
              // chunk (importing the sync React graph one-directionally).
              // Forcing them into the sync 'vendor' chunk would drag three in
              // on first paint and risk chunk cycles.
              if (norm.includes('node_modules/@react-three/fiber/')) return undefined;
              if (norm.includes('node_modules/react-reconciler/')) return undefined;
              if (norm.includes('node_modules/its-fine/')) return undefined;
              if (norm.includes('node_modules/suspend-react/')) return undefined;
              if (id.includes('react-router-dom')) return 'vendor-router';
              if (id.includes('@supabase')) return 'vendor-supabase';
              // Everything React-related (react, react-dom, scheduler,
              // react-reconciler, its-fine, zustand, @react-three/fiber) stays
              // together here so Rollup emits no cycles.
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
      drop: ['debugger'],
      legalComments: 'none',
    },
  };
});
