/** UI contract fixtures only: all API calls are intercepted, with no real scans or database writes. */
import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { comparisonFixture } from './analysis.compare-fixture';
const runtimeErrors = new WeakMap<Page, string[]>();
test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors: string[] = [];
  runtimeErrors.set(page, errors);
  page.on('pageerror', error => errors.push(error.message));
});
test.afterEach(async ({ page }) => {
  expect(runtimeErrors.get(page), 'No browser runtime errors').toEqual([]);
});
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const tenant = id(900), sbomId = id(800), projectId = id(700), productId = id(600);
const sbom = { id: sbomId, display_id: 80, sbom_name: 'Gateway service', sbom_version: '2.4.0', productver: '2.4.0', projectid: projectId, project_name: 'Customer platform', product_id: productId, product_name: 'API Gateway', status: 'validated', format: 'CycloneDX', created_on: '2026-10-22T08:00:00Z', processing_eligibility: { eligible: true } };
const runs = Array.from({ length: 107 }, (_, i) => ({
  id: id(i + 1), display_id: i + 1, sbom_id: sbomId, sbom_name: sbom.sbom_name, sbom_version: sbom.sbom_version,
  project_id: projectId, project_name: sbom.project_name, product_id: productId, product_name: sbom.product_name,
  run_status: i % 5 === 0 ? 'PARTIAL' : 'FINDINGS', source: 'NVD,OSV', total_components: 12, components_with_cpe: 9,
  total_findings: 8, critical_count: 1, high_count: 2, medium_count: 3, low_count: 1, unknown_count: 1, query_error_count: i % 5 === 0 ? 1 : 0,
  completed_on: '2026-10-22T10:20:00Z', started_on: '2026-10-22T10:19:00Z', duration_ms: 60000, is_current: true, processing_eligibility: { eligible: true },
}));
async function fixture(page: Page) {
  await page.context().addCookies([{ name: '__Host-sbom-session', value: 'analysis-ui-fixture', url: test.info().project.use.baseURL as string, secure: true, httpOnly: true, sameSite: 'Lax' }]);
  const observed: { path: string; search: string; method: string; tenant?: string; body?: string | null }[] = [];
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/backend', '');
    observed.push({ path, search: url.search, method: request.method(), tenant: request.headers()['x-tenant-id'], body: request.postData() });
    let body: unknown = [];
    const headers: Record<string, string> = {};
    if (path === '/health') body = { status: 'ok' };
    else if (path === '/api/auth/session') body = { authenticated: true, provider: 'NATIVE' };
    else if (path === '/api/auth/me') body = { user_id: id(901), display_name: 'Fixture analyst', tenant_id: tenant, is_platform_admin: false,
      roles: ['TENANT_ADMIN'], permissions: ['analysis:read', 'analysis:run', 'sbom:read', 'project:read', 'dashboard:read'],
      auth_context: { status: 'ACTIVE', tenant_context: { available_tenants: [{ id: tenant, name: 'Example enterprise', status: 'ACTIVE', membership_status: 'ACTIVE', current_role: 'TENANT_ADMIN' }] } } };
    else if (path === '/api/projects') body = [{ id: projectId, project_name: sbom.project_name }];
    else if (path === '/api/sboms') body = [sbom];
    else if (path === `/api/sboms/${sbomId}`) body = sbom;
    else if (path.endsWith('/info')) body = { format: 'CycloneDX', spec_version: '1.6', component_count: 12, has_cpes: true, has_purls: true, ecosystems: ['npm'], components_preview: ['express'] };
    else if (path === '/api/analysis/config') body = { github_configured: false, nvd_key_configured: true, max_concurrency: 3 };
    else if (path.endsWith('/posture-versions')) body = { items: [{ target_sbom_id: sbomId, posture_sbom_id: sbomId, analysis_run_id: id(107), analysis_status: 'ANALYZED',
      current_sbom: { id: sbomId, name: sbom.sbom_name, version: sbom.sbom_version }, latest_uploaded: { id: sbomId, name: sbom.sbom_name, version: sbom.sbom_version }, latest_analyzed: { id: sbomId, name: sbom.sbom_name, version: sbom.sbom_version }, posture_sbom: { id: sbomId, name: sbom.sbom_name, version: sbom.sbom_version }, coverage_incomplete: false, last_known_posture: false, warning: null }] };
    else if (path === '/api/v1/compare') body = { ...comparisonFixture, run_a: { ...comparisonFixture.run_a, sbom_version: '2.3.0' }, run_b: { ...comparisonFixture.run_b, sbom_version: '2.4.0' } };
    else if (path.endsWith('/export')) { await route.fulfill({ contentType: 'application/json', headers: { 'Content-Disposition': 'attachment; filename="comparison.json"' }, body: JSON.stringify(comparisonFixture) }); return; }
    else if (path === '/api/runs/aggregate') body = { total_runs: 107, by_outcome: { no_issues: 0, with_findings: 85, source_errors: 22, failed: 0, other: 0 }, total_findings: 856 };
    else if (path === '/api/runs') {
      let matches = [...runs].reverse();
      const status = url.searchParams.get('run_status'), q = url.searchParams.get('q');
      if (status) matches = matches.filter(run => run.run_status === status);
      if (q) matches = matches.filter(run => run.id.includes(q) || run.sbom_name.toLowerCase().includes(q.toLowerCase()));
      if (url.searchParams.get('sort_direction') === 'asc') matches.reverse();
      headers['X-Total-Count'] = String(matches.length);
      const size = Number(url.searchParams.get('page_size') || 50), page = Number(url.searchParams.get('page') || 1);
      body = matches.slice((page - 1) * size, page * size);
    } else if (path === '/api/runs/recent' || path === '/api/runs/search') body = runs.slice(-2).reverse();
    else if (path.startsWith('/api/runs/')) body = runs.find(run => path === `/api/runs/${run.id}`) || [];
    else if (path.endsWith('/analyze/stream')) {
      await route.fulfill({ contentType: 'text/event-stream', body: [
        ['progress', { phase: 'started', runId: id(107) }], ['progress', { phase: 'parsed', components: 12, runId: id(107) }],
        ['progress', { source: 'OSV', status: 'complete', findings: 8, errors: 0 }],
        ['progress', { source: 'NVD', status: 'error', findings: 0, errors: 1, error: 'Source timeout' }],
        ['complete', { runId: id(107), status: 'PARTIAL', total: 8, critical: 1, high: 2, medium: 3, low: 1, unknown: 1, duration_ms: 1000 }],
      ].map(([event, data]) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`).join('') }); return;
    }
    await route.fulfill({ json: body, headers });
  });
  return observed;
}
for (const width of [1440, 768, 390]) test(`Consolidated configuration comes first at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1000 });
  const observed = await fixture(page);
  await page.goto('/analysis?tab=consolidated');
  await expect(page.getByRole('heading', { name: 'Consolidated Analysis', exact: true })).toBeVisible();
  const configuration = page.getByRole('heading', { name: 'Analysis configuration' });
  await expect(configuration).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run analysis', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run analysis', exact: true })).toBeDisabled();
  expect(await configuration.evaluate(element => element.getBoundingClientRect().top)).toBeLessThan(500);
  await expect(page.getByRole('table', { name: 'Recent analysis runs' }).locator('tbody tr')).toHaveCount(5);
  expect(observed.some(request => request.path.endsWith('/posture-versions'))).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: resolve(`../../docs/engineering/analysis-ui-evidence/consolidated-after-${width}.png`) });
});
test('UUID selection, source availability, scan request and partial results', async ({ page }) => {
  const observed = await fixture(page);
  await page.goto(`/analysis?tab=consolidated&sbom=${sbomId}`);
  await expect(page.getByRole('button', { name: 'Run analysis', exact: true })).toBeEnabled();
  await expect(page.getByText('Selected version', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /GHSA/ })).toBeDisabled();
  await page.getByRole('button', { name: 'Run analysis', exact: true }).click();
  await expect(page.getByText('Analysis finished', { exact: true })).toBeVisible();
  await expect(page.getByText('Source coverage is incomplete.', { exact: false })).toBeVisible();
  const start = observed.find(request => request.method === 'POST' && request.path.endsWith('/analyze/stream'))!;
  expect(start.tenant).toBe(tenant);
  expect(JSON.parse(start.body!).sources).toEqual(['NVD', 'OSV']);
  await expect(page.getByRole('region', { name: 'Analysis execution' }).getByRole('paragraph').filter({ hasText: /^8$/ })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('region', { name: 'Analysis execution' }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: resolve('../../docs/engineering/analysis-ui-evidence/analysis-results-after.png') });
});
test('server history pagination, filtering, JSON download and comparison entry', async ({ page }) => {
  const observed = await fixture(page);
  await page.goto('/analysis?tab=runs');
  const table = page.getByRole('table', { name: 'Analysis runs table' });
  await expect(table.locator('tbody tr')).toHaveCount(25);
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('link', { name: '#82', exact: true })).toBeVisible();
  expect(observed.some(request => request.path === '/api/runs' && new URLSearchParams(request.search).get('page') === '2')).toBe(true);
  await page.getByRole('searchbox', { name: 'Search runs' }).fill(id(1));
  await expect(table.locator('tbody tr')).toHaveCount(1);
  await expect(page.getByRole('link', { name: '#1', exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON', exact: true }).click();
  const download = await downloadPromise;
  const exported = JSON.parse(readFileSync((await download.path())!, 'utf8'));
  expect(exported.runs).toHaveLength(1);
  expect(exported.runs[0].id).toBe(id(1));
  await page.getByRole('searchbox', { name: 'Search runs' }).fill('');
  await expect(table.locator('tbody tr')).toHaveCount(25);
  await page.getByRole('checkbox', { name: 'Select Run #107 for comparison' }).check();
  await page.getByRole('checkbox', { name: 'Select Run #106 for comparison' }).check();
  await page.getByRole('button', { name: 'Compare (2/2)', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/analysis/compare\\?run_a=${id(107)}&run_b=${id(106)}`));
});
test('empty and failed history retains usable filters', async ({ page }) => {
  await fixture(page);
  await page.goto('/analysis?tab=runs');
  await page.getByRole('searchbox', { name: 'Search runs' }).fill('nothing matches');
  await expect(page.getByText(/No analysis runs match/)).toBeVisible();
  await page.route('**/api/backend/api/runs?**', route => route.fulfill({ status: 503, json: { detail: 'History temporarily unavailable' } }));
  await page.getByRole('searchbox', { name: 'Search runs' }).fill('Gateway');
  await expect(page.getByText('Could not load analysis runs')).toBeVisible();
  await expect(page.getByRole('searchbox', { name: 'Search runs' })).toBeEnabled();
});


test('Compare retains finding deltas, SBOM versions and JSON export', async ({ page }) => {
  await fixture(page);
  await page.goto(`/analysis/compare?run_a=${id(1)}&run_b=${id(2)}`);
  await expect(page.getByRole('heading', { name: 'Compare runs', exact: true })).toBeVisible();
  await expect(page.getByLabel('Compared SBOM versions')).toContainText('Version: 2.3.0');
  await expect(page.getByLabel('Compared SBOM versions')).toContainText('Version: 2.4.0');
  await expect(page.getByText('CVE-2024-12345', { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: resolve('../../docs/engineering/analysis-ui-evidence/compare-after.png') });
  await page.getByRole('button', { name: 'Export', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Export comparison' });
  const downloaded = page.waitForEvent('download');
  await dialog.getByRole('button', { name: 'JSON Full payload for automation.' }).click();
  expect((await downloaded).suggestedFilename()).toBe('comparison.json');
});

test('dark theme and Runs remain within the desktop and mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await fixture(page);
  await page.goto('/analysis?tab=runs');
  await expect(page.getByRole('table', { name: 'Analysis runs table' }).locator('tbody tr')).toHaveCount(25);
  await page.screenshot({ path: resolve('../../docs/engineering/analysis-ui-evidence/runs-after-1440.png') });
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.screenshot({ path: resolve('../../docs/engineering/analysis-ui-evidence/runs-dark-1440.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.goto('/analysis?tab=consolidated');
  await expect(page.getByRole('heading', { name: 'Analysis configuration' })).toBeVisible();
  await page.screenshot({ path: resolve('../../docs/engineering/analysis-ui-evidence/consolidated-dark-390.png') });
});
