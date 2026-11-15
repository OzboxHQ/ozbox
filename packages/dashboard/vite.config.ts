import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const root = fileURLToPath(new URL('.', import.meta.url));

// `ozbox serve` embeds `dist/` into the binary. Its Content-Security-Policy forbids inline and remote scripts, so
// nothing is inlined into the page.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': root.replace(/\/$/, '') } },
  build: { assetsInlineLimit: 0, sourcemap: false },
  server: {
    // `npm run dev` proxies the API to a running `ozbox serve` (set OZBOX_SERVE to its origin).
    proxy: { '/v1': process.env['OZBOX_SERVE'] ?? 'http://127.0.0.1:7878' },
  },
  test: { include: ['src/**/*.test.ts', 'tests/**/*.test.ts'], environment: 'node' },
});
