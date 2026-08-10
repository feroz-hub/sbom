import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// vitest config — mirrors the `@/*` path alias from tsconfig.json so tests
// can ``import { … } from '@/lib/env'``. Default environment is ``node`` so
// pure-helper tests don't pay the jsdom startup cost; component tests opt
// into jsdom via the ``// @vitest-environment jsdom`` pragma at the top of
// the file (or by living under ``components/**``).
export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(fileURLToPath(new URL('./src', import.meta.url))),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    setupFiles: ['./vitest.setup.ts'],
    // Component tests opt into jsdom via the
    // ``// @vitest-environment jsdom`` pragma at the top of the file.
    // (vitest 4 removed environmentMatchGlobs, so we pin per-file.)
  },
});
