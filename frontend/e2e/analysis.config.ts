import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '.', testMatch: 'analysis.spec.ts', workers: 1, timeout: 90_000,
  expect: { timeout: 30_000 },
  use: { baseURL: process.env.ANALYSIS_E2E_ORIGIN || 'https://localhost:13001', channel: 'chrome', headless: true, ignoreHTTPSErrors: false, trace: 'off', screenshot: 'only-on-failure' },
  outputDir: '/tmp/sbom-analysis-ui-browser', reporter: [['list']],
});
