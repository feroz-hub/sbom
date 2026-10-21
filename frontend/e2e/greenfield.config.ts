import { defineConfig } from '@playwright/test';
import { homedir } from 'node:os';
export default defineConfig({
  testDir: '.', testMatch: 'greenfield.spec.ts', workers: 1,
  timeout: 180000, expect: { timeout: 30000 },
  use: { baseURL: 'https://localhost:13000', channel: 'chrome', ignoreHTTPSErrors: false, headless: true, trace: 'off' },
  outputDir: process.env.GREENFIELD_BROWSER_RESULTS ?? `${homedir()}/.sbom-greenfield-uuid/browser-results`,
  reporter: [['list']],
});
