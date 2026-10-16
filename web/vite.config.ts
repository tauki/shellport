import { defineConfig } from 'vite';
import { resolve } from 'node:path';

export default defineConfig({
  root: resolve(import.meta.dirname),
  build: { outDir: '../internal/web/dist', emptyOutDir: true },
  server: {
    host: '127.0.0.1',
    proxy: { '/api': { target: 'http://127.0.0.1:8088', ws: true } },
  },
});
