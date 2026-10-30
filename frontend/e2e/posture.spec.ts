/** Actual UI with intercepted API fixtures. No application database or external provider calls. */
import { test, expect, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import catalogue from '../src/test/permissionCatalogue.json';
import { FULL_DETAIL } from '../src/components/vulnerabilities/CveDetailDialog/__tests__/fixtures';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const tenant = id(900), sbomId = id(5), projectId = id(7), productId = id(8);
const version = { id: sbomId, name: 'Gateway service', version: '2.4.0' };
const sbom = { id: sbomId, display_id: 5, sbom_name: version.name, sbom_version: version.version, projectid: projectId,
  product_id: productId, project_name: 'Customer platform', product_name: 'Gateway', status: 'validated', format: 'CycloneDX', processing_eligibility: { eligible: true } };
const posture = Array.from({ length: 107 }, (_, i) => ({
  application_name: `Application ${i}`, target_sbom_id: i === 0 ? sbomId : id(i + 100), posture_sbom_id: i === 0 ? sbomId : id(i + 100), product_id: productId,
  current_sbom: version, latest_uploaded: version, latest_analyzed: version, posture_sbom: version,
  analysis_run_id: i === 1 ? null : id(10), analysis_completed_on: '2026-10-22T10:00:00Z', analysis_status: i === 1 ? 'ANALYSIS_PENDING' : 'ANALYZED',
  analysis_finding_rows: i === 1 ? null : 81, last_known_posture: i === 2, coverage_incomplete: i === 3, designation_required: false,
  warning: i === 2 ? 'A newer SBOM is awaiting successful analysis.' : null,
}));
const row = { id: id(50), canonical_vulnerability_id: 'CVE-2026-4001', aliases: [], severity: 'CRITICAL',
  component_id: id(11), component_name: 'openssl', component_version: '1.1.1', project_id: projectId, project_name: sbom.project_name,
  product_id: productId, product_name: sbom.product_name, sbom_id: sbomId, sbom_name: sbom.sbom_name,
  analyzer_detection_state: 'DETECTED', analyzer_sources: ['NVD'], vex_source: null, native_vex_status: null,
  effective_status: 'UNDER_INVESTIGATION', reconciliation_status: 'ANALYZER_ONLY', justification: null,
  assigned_to: null, reviewed_by: null, last_seen_at: '2026-10-22T10:00:00Z', row_version: 1, needs_review: false };
const summary = { total: 1, total_contexts: 1, mapped_total: 1, affected_count: 0, not_affected_count: 0, fixed_count: 0,
  under_investigation_count: 1, needs_review_count: 0, unresolved_mapping_count: 0, matched_count: 0,
  analyzer_only_count: 1, vex_only_count: 0, conflict_review_count: 0, revalidation_required_count: 0, top_affected_components: [] };
const evidenceDir = resolve('../../docs/engineering/shared-version-evidence');
mkdirSync(evidenceDir, { recursive: true });

async function fixture(page: Page, options: { empty?: boolean; error?: boolean; denied?: boolean; pending?: Promise<void> } = {}) {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.context().addCookies([{ name: '__Host-sbom-session', value: 'posture-ui-fixture', url: test.info().project.use.baseURL as string,
    secure: true, httpOnly: true, sameSite: 'Lax' }]);
  const requests: { path: string; tenant?: string; search: string; method: string }[] = [];
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/backend', '');
    requests.push({ path, tenant: request.headers()['x-tenant-id'], search: url.search, method: request.method() });
    let body: unknown = [];
    if (path === '/health') body = { status: 'ok' };
    else if (path === '/api/auth/session') body = { authenticated: true, provider: 'NATIVE' };
    else if (path === '/api/auth/me') body = { user_id: id(901), display_name: 'Fixture analyst', tenant_id: tenant, is_platform_admin: false,
      roles: ['TENANT_ADMIN'], permissions: options.denied ? [] : catalogue.permissions,
      auth_context: { status: 'ACTIVE', tenant_context: { available_tenants: [{ id: tenant, name: 'Example enterprise', status: 'ACTIVE', membership_status: 'ACTIVE', current_role: 'TENANT_ADMIN' }] } } };
    else if (path === '/api/vex/investigations') {
      if (options.pending) await options.pending;
      if (options.error) { await route.fulfill({ status: 503, json: { detail: 'Temporarily unavailable' } }); return; }
      body = { items: options.empty ? [] : [row], total: options.empty ? 0 : 1, limit: 50, offset: 0, posture: options.empty ? [] : posture };
    } else if (path === `/api/vex/investigations/${row.id}`) body = { id: row.id, sbom_id: sbomId, sbom_name: sbom.sbom_name,
      project_name: sbom.project_name, product_name: sbom.product_name, row_version: 1,
      vulnerability: { canonical_vulnerability_id: row.canonical_vulnerability_id, aliases: [], severity: 'CRITICAL', references: [] },
      component: { component_id: id(11), name: 'openssl', version: '1.1.1' },
      analyzer_evidence: { detection_state: 'DETECTED', sources: ['NVD'], analysis_run_id: id(10) }, imported_vex: [],
      internal_decision: { effective_status: null }, effective_status: 'UNDER_INVESTIGATION', reconciliation_status: 'ANALYZER_ONLY', history: [],
      capabilities: { can_update: false, can_assign: false, can_map: false, eligible_roles: [], candidates: [],
        owner: { id: null, label: 'Unassigned', roles: [], is_self: false, active: false }, read_only_reason: 'Read-only fixture evidence' } };
    else if (path === '/api/vex/investigations/summary' || path === '/dashboard/vex') body = summary;
    else if (path === '/api/vex/investigations/assignees') body = { items: [], total: 0, limit: 50, offset: 0 };
    else if (path === '/dashboard/filter-options/projects') body = { items: [{ id: projectId, name: sbom.project_name }] };
    else if (path === '/dashboard/filter-options/applications') body = { items: [{ id: productId, name: sbom.product_name }] };
    else if (path === '/dashboard/filter-options/sboms') body = { items: [{ id: sbomId, name: sbom.sbom_name }] };
    else if (path === `/api/products/${productId}`) body = { id: productId, project_id: projectId, name: 'Gateway', current_sbom_id: sbomId, current_sbom_mode: 'MANUAL_PIN' };
    else if (path.endsWith('/sboms')) body = [sbom];
    else if (path.includes('/cves/')) body = FULL_DETAIL;
    else if (path.endsWith('/logical-sboms')) body = { items: [], total: 0 };
    else if (path === '/dashboard/posture-versions') body = { items: posture };
    else if (path.endsWith('/schedules')) body = { items: [], total: 0 };
    await route.fulfill({ json: body });
  });
  return { requests, errors };
}

for (const width of [1440, 768, 390]) test(`VEX prioritizes triage with 107 lineages at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1000 });
  const { requests, errors } = await fixture(page);
  await page.goto('/vex-investigation');
  await expect(page.getByRole('heading', { name: 'VEX Investigation', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review version evidence' })).toHaveAttribute('aria-expanded', 'false');
  await expect(page.getByRole('table', { name: 'SBOM version evidence table' })).toHaveCount(0);
  const search = page.getByRole('searchbox', { name: 'Search vulnerability' });
  await expect(search).toBeVisible();
  expect(await search.evaluate(element => element.getBoundingClientRect().top)).toBeLessThan(850);
  expect(requests.find(request => request.path === '/api/vex/investigations')?.tenant).toBe(tenant);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: resolve(evidenceDir, `vex-after-${width}.png`) });
  await page.getByRole('button', { name: 'Review version evidence' }).focus();
  await page.keyboard.press('Enter');
  const table = page.getByRole('table', { name: 'SBOM version evidence table' });
  await expect(table.locator('tbody tr')).toHaveCount(10);
  const evidence = page.getByRole('region', { name: 'SBOM version evidence', exact: true });
  await evidence.getByRole('button', { name: 'Last page' }).click();
  await expect(table.getByText('Application 106', { exact: true })).toBeVisible();
  await expect(table.locator('tbody tr')).toHaveCount(7);
  await page.getByRole('searchbox', { name: 'Search version evidence' }).fill('Application 73');
  await expect(table.getByText('Application 73', { exact: true })).toBeVisible();
  await expect(table.locator('tbody tr')).toHaveCount(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: resolve(evidenceDir, `vex-evidence-${width}.png`) });
  await page.getByRole('button', { name: 'Collapse version evidence' }).click();
  await expect(table).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('selected SBOM scope, investigation details and dark theme retain supported actions', async ({ page }) => {
  const { requests, errors } = await fixture(page);
  await page.goto(`/vex-investigation?project_id=${projectId}&product_id=${productId}&sbom_id=${sbomId}`);
  await expect(page.getByText('1 version lineage in this scope.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.screenshot({ path: resolve(evidenceDir, 'vex-dark.png') });
  await page.getByRole('button', { name: 'Update VEX', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Selected investigation context' })).toContainText('openssl 1.1.1');
  await expect(page.getByText('Read-only fixture evidence', { exact: false })).toBeVisible();
  expect(requests.some(request => request.path === `/api/vex/investigations/${row.id}`)).toBe(true);
  expect(requests.filter(request => request.method !== 'GET')).toEqual([]);
  expect(errors).toEqual([]);
});

test('empty, failed and loading investigations never mount portfolio records', async ({ page }) => {
  let release!: () => void;
  const pending = new Promise<void>(done => { release = done; });
  await fixture(page, { empty: true, pending });
  await page.goto('/vex-investigation');
  await expect(page.getByText('Updating investigations…', { exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'SBOM version evidence table' })).toHaveCount(0);
  release();
  await expect(page.getByText('No investigations exist', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review version evidence' })).toHaveCount(0);
  await page.route('**/api/backend/api/vex/investigations?**', route => route.fulfill({ status: 503, json: { detail: 'Temporarily unavailable' } }));
  await page.getByRole('searchbox', { name: 'Search vulnerability' }).fill('CVE');
  await expect(page.getByText('Unable to load investigations.', { exact: false })).toBeVisible();
  await expect(page.getByRole('searchbox', { name: 'Search vulnerability' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Retry', exact: true })).toBeVisible();
});

test('product details use the same compact shared evidence without displacing selection', async ({ page }) => {
  const { errors } = await fixture(page);
  await page.goto(`/products/${productId}`);
  await expect(page.getByRole('button', { name: 'Review version evidence' })).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Current SBOM selection policy' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'SBOM version evidence table' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Review version evidence' }).click();
  await expect(page.getByRole('table', { name: 'SBOM version evidence table' }).locator('tbody tr')).toHaveCount(10);
  await page.screenshot({ path: resolve(evidenceDir, 'product-version-evidence.png') });
  expect(errors).toEqual([]);
});

test('permission denial does not request investigation records', async ({ page }) => {
  const { requests, errors } = await fixture(page, { denied: true });
  await page.goto('/vex-investigation');
  await expect(page.getByRole('heading', { name: 'Access restricted', exact: true })).toBeVisible();
  expect(requests.filter(request => request.path === '/api/vex/investigations')).toEqual([]);
  expect(errors).toEqual([]);
});
