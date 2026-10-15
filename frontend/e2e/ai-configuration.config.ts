import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '.',
  testMatch: 'ai-configuration.browser.ts',
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 20_000 },
  use: {
    baseURL: process.env.AI_UI_BASE_URL || 'https://localhost:13000',
    ignoreHTTPSErrors: true,
    headless: true,
    launchOptions: process.env.CHROME_BIN
      ? { executablePath: process.env.CHROME_BIN, args: ['--no-sandbox'] }
      : undefined,
    screenshot: 'only-on-failure',
  },
  outputDir: '/tmp/sbom-ai-ui/browser-results',
  reporter: 'list',
});
