import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';





const envDir = '..';

export default defineConfig(({ mode }) => {



  const env = loadEnv(mode, envDir, '');
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8000';

  return {
    envDir,
    plugins: [react()],
    resolve: {

      dedupe: ['react', 'react-dom'],
    },
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






              const norm = id.replace(/\\/g, '/');
              if (norm.includes('node_modules/three/')) return 'vendor-three';
              if (norm.includes('node_modules/maath/')) return 'vendor-three';
              if (norm.includes('node_modules/cobe/')) return 'vendor-cobe';





              if (norm.includes('node_modules/@react-three/fiber/')) return undefined;
              if (norm.includes('node_modules/react-reconciler/')) return undefined;
              if (norm.includes('node_modules/its-fine/')) return undefined;
              if (norm.includes('node_modules/suspend-react/')) return undefined;
              if (id.includes('react-router-dom')) return 'vendor-router';
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
