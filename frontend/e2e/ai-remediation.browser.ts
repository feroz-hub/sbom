import { test as base, expect, chromium, type Page, type APIResponse } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const manifest = JSON.parse(readFileSync(process.env.REPAIR_E2E_MANIFEST!, 'utf8'));
const headers = { Origin: manifest.origin };
const api = (path: string) => `/api/backend${path}`;
// A fresh browser per case keeps long-lived SSE connections and native login
// sessions isolated. Every request still uses the real application/IAM stack.
const test = base.extend({
  page: async ({}, use) => {
    const browser = await chromium.launch({ channel: process.env.REMEDIATION_BROWSER_CHANNEL, args: ['--disable-http2'] });
    const context = await browser.newContext({ baseURL: manifest.origin, ignoreHTTPSErrors: true });
    try { await use(await context.newPage()); } finally { await browser.close(); }
  },
});
const visit = (page: Page, path: string) => page.goto(path, { waitUntil: 'domcontentloaded', timeout: 30_000 });
async function login(page: Page, role = 'analyst') {
  // Authenticate through the real BFF/IAM service; never fabricate tokens or grants.
  const response = await page.request.post('/api/auth/native/login', {
    headers, data: { email: manifest.users[role].email, password: manifest.users[role].password },
  });
  expect(response.status()).toBe(200);
}
async function shot(page: Page, name: string) {
  await page.screenshot({ path: join(test.info().outputDir, name + '.png'), fullPage: false });
}
async function control(page: Page, mode = 'success', delay = 200) {
  const response = await page.request.post(manifest.mock_url + '/__control', { data: { mode, delay } });
  expect(response.status()).toBe(200);
}
async function pollBatch(page: Page, runId: string, id: string) {
  let last: any;
  await expect.poll(async () => {
    const r = await page.request.get(api(`/api/v1/runs/${runId}/ai-fixes/batches/${id}`), { headers });
    expect(r.status()).toBe(200); const detail = await r.json(); last = detail.progress;
    return last.status;
  }, { timeout: 90_000, intervals: [300, 1000] }).toMatch(/complete|cancelled|paused_budget|failed/);
  return last;
}

test('synthetic Log4j and 75-finding batch with durable progress, cache and reload', async ({ page }) => {
  await login(page);
  await visit(page, '/analysis/' + manifest.runs.bulk.id);
  const button = page.getByRole('button', { name: 'Generate AI fixes', exact: true });
  await expect(button).toBeEnabled();
  await expect(page.getByTestId('ai-batch-cta-label')).toContainText('75');
  const style = await button.evaluate(el => ({ color: getComputedStyle(el).color, background: getComputedStyle(el).backgroundColor, opacity: getComputedStyle(el).opacity }));
  expect(style.opacity).toBe('1'); expect(style.background).not.toBe('rgba(0, 0, 0, 0)');
  console.log('Primary control computed style:', style);
  await shot(page, 'bulk-light-desktop');
  await page.evaluate(() => document.documentElement.classList.add('dark'));
  await shot(page, 'bulk-dark-desktop');
  await page.setViewportSize({ width: 390, height: 844 });
  await button.scrollIntoViewIfNeeded();
  await expect(button).toBeInViewport();
  await shot(page, 'bulk-dark-mobile');
  await page.evaluate(() => document.documentElement.classList.remove('dark'));
  await shot(page, 'bulk-light-mobile');
  await page.setViewportSize({ width: 1440, height: 1000 });

  // Real individual POST, cache GET, usage are exercised without a model call outside localhost.
  const finding = manifest.runs.individual.findings[0];
  await visit(page, '/analysis/' + manifest.runs.individual.id);
  await page.getByRole('button', { name: 'Open CVE detail for CVE-2021-44228', exact: true }).click();
  const generate = page.getByRole('button', { name: 'Generate AI remediation', exact: true });
  await expect(generate).toBeEnabled(); await generate.scrollIntoViewIfNeeded();
  await shot(page, 'individual-light');
  const generated = page.waitForResponse(r => r.url().includes(`/findings/${finding}/ai-fix`) && r.request().method() === 'POST');
  await generate.click();
  let r: Pick<APIResponse, 'status' | 'json'> = await generated;
  expect(r.status()).toBe(200);
  const individual = await r.json();
  expect(individual.error).toBeNull(); expect(individual.result.metadata.model_used).toBe('gpt-4o');
  expect(individual.result.bundle.upgrade_command.target_version).toBe('2.17.1');
  expect(individual.result.metadata.total_cost_usd).toBeGreaterThan(0);
  r = await page.request.get(api(`/api/v1/findings/${finding}/ai-fix`), { headers });
  expect((await r.json()).result.metadata.cache_hit).toBe(true);

  await page.keyboard.press('Escape');
  await visit(page, '/analysis/' + manifest.runs.bulk.id);
  await control(page);
  r = await page.request.post(api(`/api/v1/runs/${manifest.runs.small.id}/ai-fixes`), { headers, data: {} });
  expect(r.status()).toBe(200);
  const small = await r.json(); expect(small.enqueued).toBe(true);
  const smallDone = await pollBatch(page, manifest.runs.small.id, small.batch_id);
  expect(smallDone.generated).toBe(3); expect(smallDone.failed).toBe(0);

  const posted = page.waitForResponse(r => r.url().endsWith(`/runs/${manifest.runs.bulk.id}/ai-fixes`) && r.request().method() === 'POST');
  await button.click();
  r = await posted; expect(r.status()).toBe(200);
  const bulk = await r.json(); expect(bulk.enqueued).toBe(true); expect(bulk.total).toBe(75);
  await expect(page.getByRole('button', { name: 'Cancel', exact: true }).first()).toBeVisible();
  const bulkDone = await pollBatch(page, manifest.runs.bulk.id, bulk.batch_id);
  expect(bulkDone.generated).toBe(75); expect(bulkDone.failed).toBe(0); expect(bulkDone.remaining).toBe(0);
  await expect(page.getByText('AI remediation complete', { exact: true })).toBeVisible();
  r = await page.request.get(api(`/api/v1/runs/${manifest.runs.bulk.id}/ai-fixes/batches`), { headers });
  const durable = await r.json();
  expect(durable.items.find((b: any) => b.batch_id === bulk.batch_id)).toMatchObject({ status: 'complete', generated_count: 75, failed_count: 0 });
  r = await page.request.get(api(`/api/v1/runs/${manifest.runs.bulk.id}/ai-fixes`), { headers });
  const fixes = await r.json(); expect(fixes.total).toBe(75);
  await expect(page.getByRole('button', { name: 'Open AI remediation for CVE-2021-44228', exact: true }).first()).toBeVisible();
  await shot(page, 'bulk-complete');
  await page.reload();
  await expect(page.getByText('AI remediation complete', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open AI remediation for CVE-2021-44228', exact: true }).first()).toBeVisible();
  const metrics = await (await page.request.get(manifest.mock_url + '/__metrics')).json();
  expect(metrics.calls.length).toBe(79);
  expect(metrics.calls.every((call: any) => call.model === 'gpt-4o' && call.endpoint === '/v1/chat/completions' && call.strict_schema)).toBe(true);
  writeFileSync(join(test.info().outputDir, 'batch-evidence.json'), JSON.stringify({ style, individual, smallDone, bulkDone, durable, cacheCount: fixes.total, requests: metrics.calls.length }, null, 2));
});

for (const role of ['viewer', 'foreign']) {
  test(`${role} denial preserves tenant isolation and makes no provider call`, async ({ page }) => {
    await login(page, role);
    const before = await (await page.request.get(manifest.mock_url + '/__metrics')).json();
    if (role === 'viewer') {
      await visit(page, '/analysis/' + manifest.runs.cancel.id);
      const button = page.getByRole('button', { name: 'Generate AI fixes', exact: true });
      await expect(button).toBeDisabled();
      await button.locator('..').focus();
      await expect(page.getByRole('tooltip')).toContainText('permission to run vulnerability analysis');
      await shot(page, 'viewer-permission-denied');
    }
    const response = await page.request.post(api(`/api/v1/runs/${manifest.runs.cancel.id}/ai-fixes`), { headers, data: {} });
    expect(response.status()).toBe(role === 'viewer' ? 403 : 404);
    const read = await page.request.get(api(`/api/v1/findings/${manifest.runs.individual.findings[0]}/ai-fix`), { headers });
    expect(read.status()).toBe(role === 'viewer' ? 200 : 404);
    const after = await (await page.request.get(manifest.mock_url + '/__metrics')).json();
    expect(after.calls.length).toBe(before.calls.length);
  });
}

test('cancellation, cache-aware retry, provider failures and budget enforcement', async ({ page }) => {
  await login(page);
  await control(page, 'success', 500);
  const run = manifest.runs.cancel.id;
  await visit(page, '/analysis/' + run);
  await expect(page.getByRole('button', { name: 'Generate AI fixes', exact: true })).toBeEnabled();
  const accepted = page.waitForResponse(r => r.url().endsWith(`/runs/${run}/ai-fixes`) && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Generate AI fixes', exact: true }).click();
  let r: Pick<APIResponse, 'status' | 'json'> = await accepted;
  expect(r.status()).toBe(200); const initial = await r.json(); expect(initial.enqueued).toBe(true);
  const cancel = page.getByRole('button', { name: 'Cancel', exact: true }).first();
  await expect(cancel).toBeVisible(); await cancel.click();
  const cancelled = await pollBatch(page, run, initial.batch_id);
  expect(cancelled.status).toBe('cancelled'); expect(cancelled.remaining).toBeGreaterThan(0);
  expect(cancelled.generated + cancelled.failed + cancelled.from_cache + cancelled.remaining).toBe(15);
  await control(page);
  await expect(page.getByRole('button', { name: 'Generate AI fixes', exact: true })).toBeEnabled();
  const posted = page.waitForResponse(r => r.url().endsWith(`/runs/${run}/ai-fixes`) && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Generate AI fixes', exact: true }).click();
  const retry = await (await posted).json();
  const retried = await pollBatch(page, run, retry.batch_id);
  expect(retried.status).toBe('complete'); expect(retried.from_cache).toBe(cancelled.generated);
  expect(retried.from_cache + retried.generated).toBe(15);

  await control(page, 'permission');
  await visit(page, '/analysis/' + manifest.runs.errors.id);
  await page.getByRole('button', { name: 'Open CVE detail for CVE-2021-44228', exact: true }).first().click();
  const generate = page.getByRole('button', { name: 'Generate AI remediation', exact: true });
  await expect(generate).toBeEnabled(); await generate.click();
  await expect(page.getByRole('alert').filter({ hasText: 'Check model permissions in Settings.' })).toBeVisible();
  await expect(generate).toBeDisabled(); await shot(page, 'individual-permission-error');
  await page.keyboard.press('Escape');
  await control(page, 'quota');
  r = await page.request.post(api(`/api/v1/findings/${manifest.runs.errors.findings[1]}/ai-fix`), { headers, data: {} });
  const quota = await r.json(); expect(quota.error.error_code).toBe('quota_exceeded');
  expect(JSON.stringify(quota)).not.toContain('synthetic-local-only');

  await control(page);
  const before = await (await page.request.get(manifest.mock_url + '/__metrics')).json();
  r = await page.request.post(api(`/api/v1/runs/${manifest.runs.budget.id}/ai-fixes`), { headers, data: { budget_usd: 0 } });
  const budget = await r.json(); expect(budget.enqueued).toBe(true);
  const paused = await pollBatch(page, manifest.runs.budget.id, budget.batch_id);
  expect(paused.status).toBe('paused_budget'); expect(paused.generated).toBe(0);
  const after = await (await page.request.get(manifest.mock_url + '/__metrics')).json();
  expect(after.calls.length).toBe(before.calls.length);
  writeFileSync(join(test.info().outputDir, 'failure-evidence.json'), JSON.stringify({ cancelled, retried, quota, paused, budgetProviderCalls: after.calls.length - before.calls.length }, null, 2));
});
