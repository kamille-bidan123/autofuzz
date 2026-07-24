import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  base: '/static/',
  plugins: [vue()],
  build: {
    outDir: fileURLToPath(new URL('../internal/webui/static', import.meta.url)),
    emptyOutDir: true,
    assetsDir: 'assets'
  },
  test: {
    environment: 'jsdom'
  }
});
