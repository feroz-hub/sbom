import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.', testMatch: 'posture.spec.ts', workers: 1, timeout: 60_000,
  expect: { timeout: 20_000 },
  use: { baseURL: process.env.ANALYSIS_E2E_ORIGIN || 'https://localhost:13001', channel: 'chrome', headless: true,
    ignoreHTTPSErrors: false, reducedMotion: 'reduce', trace: 'off', screenshot: 'only-on-failure' },
  outputDir: '/tmp/sbom-posture-browser', reporter: [['list']],
});
