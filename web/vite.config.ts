import { svelte } from '@sveltejs/vite-plugin-svelte';
import legacy from '@vitejs/plugin-legacy';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    svelte(),
    legacy({
      targets: ['Chrome >= 49', 'Firefox >= 52', 'Safari >= 10', 'Edge >= 15'],
      modernPolyfills: true,
      renderLegacyChunks: true
    })
  ],
  build: {
    assetsInlineLimit: 0,
    sourcemap: false,
    rolldownOptions: {
      checks: {
        pluginTimings: false
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true
      }
    }
  }
});
