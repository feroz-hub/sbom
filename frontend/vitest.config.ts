import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// Minimal vitest config — mirrors the `@/*` path alias from tsconfig.json
// so tests can `import { … } from '@/lib/env'`. Node environment is fine
// for unit tests of pure helpers; add `environment: 'jsdom'` if/when we
// start testing React components that touch the DOM.
export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(fileURLToPath(new URL('./src', import.meta.url))),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
});
