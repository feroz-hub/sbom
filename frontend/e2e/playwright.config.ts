import { defineConfig } from '@playwright/test';
import { readFileSync } from 'node:fs';
const manifest = process.env.REPAIR_E2E_MANIFEST;
if (!manifest) throw new Error('Start the isolated instance with scripts/run_sbom_repair_e2e.py');
const setup = JSON.parse(readFileSync(manifest, 'utf8'));
export default defineConfig({
  testDir: '.', testMatch: '*.spec.ts', workers: 1, timeout: 240_000,
  expect: { timeout: 60_000 }, fullyParallel: false,
  use: { baseURL: setup.origin, ignoreHTTPSErrors: true, headless: true, trace: 'off', screenshot: 'only-on-failure' },
  outputDir: process.env.REPAIR_E2E_RESULTS || '/tmp/sbom-phase1-release/browser-results',
  reporter: [['./security-reporter.ts'], ['list'], ['junit', { outputFile: '/tmp/sbom-phase1-release/browser.xml' }]],
});
