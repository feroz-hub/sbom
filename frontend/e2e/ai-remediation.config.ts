import { defineConfig } from '@playwright/test';
import { readFileSync } from 'node:fs';
const manifest = JSON.parse(readFileSync(process.env.REPAIR_E2E_MANIFEST!, 'utf8'));
export default defineConfig({
  testDir: '.', testMatch: 'ai-remediation.browser.ts', workers: 1, timeout: 180_000,
  expect: { timeout: 45_000 },
  use: { baseURL: manifest.origin, ignoreHTTPSErrors: true, headless: true, launchOptions: { args: ['--disable-http2'] }, trace: 'off', screenshot: 'only-on-failure' },
  outputDir: process.env.REMEDIATION_E2E_RESULTS || '/tmp/sbom-ai-remediation/browser-results',
  reporter: [['./security-reporter.ts'], ['list']],
});
