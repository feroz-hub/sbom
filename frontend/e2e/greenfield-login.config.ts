import { defineConfig } from '@playwright/test';
import { homedir } from 'node:os';
export default defineConfig({
  testDir: '.', testMatch: 'greenfield-login.spec.ts', workers: 1,
  timeout: 90000, expect: { timeout: 20000 }, retries: 0,
  use: { baseURL: 'https://localhost:13000', channel: 'chrome', ignoreHTTPSErrors: false, headless: true,
    trace: 'off', screenshot: 'off', video: 'off' },
  outputDir: `${homedir()}/.sbom-greenfield-uuid/login-diagnostic/playwright-results`,
  reporter: [['list']],
});
