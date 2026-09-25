import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev proxy target: `VITE_PROXY_TARGET=http://localhost:8000 npm run dev` to point elsewhere.
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8000';

export default defineConfig({
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
            if (id.includes('react') || id.includes('react-dom')) return 'vendor-react';
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
});
