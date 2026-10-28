import { defineConfig } from '@playwright/test';

if (!process.env.LAYOUT_E2E_ORIGIN || !process.env.LAYOUT_E2E_USERS_FILE) {
  throw new Error('Set LAYOUT_E2E_ORIGIN and LAYOUT_E2E_USERS_FILE to an isolated running app and its existing test users.');
}

export default defineConfig({
  testDir: '.',
  testMatch: 'layout.spec.ts',
  workers: 1,
  timeout: 600_000,
  expect: { timeout: 30_000 },
  use: {
    baseURL: process.env.LAYOUT_E2E_ORIGIN,
    channel: 'chrome',
    headless: true,
    navigationTimeout: 60_000,
    actionTimeout: 30_000,
    ignoreHTTPSErrors: false,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  outputDir: process.env.LAYOUT_E2E_RESULTS || '/tmp/sbom-layout-results',
  reporter: [['list']],
});
