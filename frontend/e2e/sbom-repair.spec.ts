import { test, expect, type Page, type APIRequestContext } from '@playwright/test';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { validSbom, repairableSbom, partialSbom, ambiguousSbom } from './fixtures';
const manifest = JSON.parse(readFileSync(process.env.REPAIR_E2E_MANIFEST!, 'utf8'));
const tenantHeaders = {'X-Tenant-ID': String(manifest.tenant_a), Origin: manifest.origin};
const hash = (value: Buffer) => createHash('sha256').update(value).digest('hex');
const api = (path: string) => `/api/backend${path}`;
const browserErrors = new WeakMap<Page, string[]>();
test.beforeEach(({ page }) => {
  const errors: string[] = [];
  browserErrors.set(page, errors);
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (/Hydration failed|Each child in a list|Cannot update a component|Warning:.*React|Invalid DOM property/.test(message.text())) errors.push(message.text());
  });
});
test.afterEach(({ page }) => {
  expect(browserErrors.get(page)).toEqual([]);
});

async function login(page: Page, role='admin') {
  await page.goto('/native-sign-in');
  await page.getByLabel('Email address').fill(manifest.users[role].email);
  await page.getByLabel('Password', {exact:true}).fill(manifest.users[role].password);
  const authenticated = page.waitForResponse(r => r.url().endsWith('/api/auth/native/login') && r.request().method() === 'POST');
  await page.getByRole('button',{name:'Sign in', exact:true}).click();
  expect((await authenticated).status()).toBe(200);
  await page.waitForURL(manifest.origin + '/');
  if (role === 'admin') {
    await expect(page.getByRole('heading',{name:'Select tenant', exact:true})).toBeVisible();
    await page.getByRole('button',{name:/Repair Tenant A/}).click();
    await expect(page.getByRole('heading',{name:'Select tenant', exact:true})).not.toBeVisible();
  }
  await page.waitForURL(manifest.origin + '/');
  // The tenant chooser disappears while auth is still loading. Wait for
  // protected content before navigating, so bootstrap cannot race this test.
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'SBOMs', exact: true }).click();
  await expect(page.getByRole('heading',{name:'SBOMs',exact:true})).toBeVisible();
}
async function upload(page: Page, doc: object | string, valid=false, filename="release-fixture.cdx.json") {
  const raw = Buffer.from(typeof doc === "string" ? doc : JSON.stringify(doc, null, 2));
  await page.getByRole('button',{name:'Upload SBOM', exact:true}).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('SBOM Name').fill(`release-${randomUUID()}`);
  await dialog.locator('input[type="file"]').setInputFiles({name:filename, mimeType:filename.endsWith('.xml') ? 'application/xml' : 'application/json',buffer:raw});
  await dialog.getByRole('combobox',{name:'Project', exact:true}).selectOption(String(manifest.project_id));
  await dialog.getByRole('combobox',{name:'Application', exact:true}).selectOption(String(manifest.product_id));
  const responsePromise = page.waitForResponse(r => r.url().includes('/api/sboms/upload') && r.request().method() === 'POST');
  await dialog.getByRole('button',{name:'Upload SBOM', exact:true}).click();
  const response = await responsePromise;
  expect(response.status()).toBe(valid ? 202 : 422);
  const body = await response.json();
  const session = valid ? body.validation_session_id : body.detail.validation_session_id;
  if (!valid) {
    await page.waitForURL(`**/repair/${session}`);
    await expect(page.getByRole('region',{name:'Deterministic SBOM auto-repair'})).toBeVisible();
  }
  return {session, raw, sbomId:body.sbom_id};
}
async function createJob(page: Page, session: string) {
  const done = page.waitForResponse(r => r.url().endsWith(`/${session}/repair`) && r.request().method()==='POST');
  await page.getByRole('button',{name:'Auto-Repair Safe Issues',exact:true}).click();
  const response = await done;
  expect(response.status()).toBe(200);
  return response.json();
}
async function original(request: APIRequestContext, session: string) {
  const response = await request.get(api(`/api/sbom-validation-sessions/${session}/download-original`),{headers:tenantHeaders});
  expect(response.status()).toBe(200);
  return response.body();
}

test('valid upload uses existing processing and creates no repair job', async ({page}) => {
  await login(page);
  const {session,raw,sbomId} = await upload(page,validSbom(),true);
  const latest = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair`),{headers:tenantHeaders});
  expect(await latest.json()).toBeNull();
  const sbom = await page.request.get(api(`/api/sboms/${sbomId}?include_raw=true`),{headers:tenantHeaders});
  const data = await sbom.json();
  expect(data.status).toBe('validated');
  expect(data.sbom_data).toBe(raw.toString());
  expect(data.product_id).toBe(manifest.product_id);
  expect(hash(await original(page.request,session))).toBe(hash(raw));
  await expect(page.getByRole('button',{name:'Auto-Repair Safe Issues'})).toHaveCount(0);
});

test('approval repairs realistic SBOM, shows diff, preserves original and application assignment', async ({page}) => {
  const errors:string[]=[];
  page.on('pageerror',error => errors.push(error.message));
  await login(page);
  const {session,raw} = await upload(page,repairableSbom());
  const panel = page.getByRole('region',{name:'Deterministic SBOM auto-repair'});
  await expect(panel).toContainText('can be safely repaired');
  const job = await createJob(page,session);
  expect(job.status).toBe('REPAIRED');
  expect(job.validation_status).toBe('PASSED');
  expect(job.errors_after).toBe(0);
  expect(job.repairs_applied).toBeGreaterThanOrEqual(4);
  expect(hash(await original(page.request,session))).toBe(hash(raw));
  await panel.getByRole('button',{name:'View Changes',exact:true}).click();
  await expect(panel).toContainText('Old Value');
  await expect(panel).toContainText('New Value');
  await expect(panel).toContainText(' Library ');
  await expect(panel).toContainText('duplicate_bom_ref');
  await expect(panel).toContainText('dangling_dependency_ref');
  const candidate = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/download`),{headers:tenantHeaders});
  const candidateBytes = await candidate.body();
  expect(hash(candidateBytes)).toBe(job.candidate_sha256);
  const approve = page.waitForResponse(r=>r.url().endsWith(`/${job.repair_job_id}/approve`));
  await panel.getByRole('button',{name:'Accept Repairs',exact:true}).click();
  expect((await approve).status()).toBe(200);
  await expect(panel).toContainText('Approval: APPROVED');
  const link = panel.getByRole('link',{name:'Open Accepted SBOM',exact:true});
  await expect(link).toBeVisible();
  const id = Number((await link.getAttribute('href'))!.split('/').pop());
  const accepted = await page.request.get(api(`/api/sboms/${id}?include_raw=true`),{headers:tenantHeaders});
  const acceptedBody = await accepted.json();
  expect(acceptedBody.sbom_data).toBe(candidateBytes.toString());
  expect(acceptedBody.product_id).toBe(manifest.product_id);
  expect(hash(await original(page.request,session))).toBe(hash(raw));
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/sboms/${id}$`));
  await expect(page.getByRole('heading',{name:'SBOM Details',exact:true})).toBeVisible();
  expect(errors).toEqual([]);
});

test('rejection retains original and cannot activate rejected candidate', async ({page}) => {
  await login(page);
  const {session,raw} = await upload(page,repairableSbom());
  const job = await createJob(page,session);
  await page.getByRole('button',{name:'View Changes',exact:true}).click();
  const rejected = page.waitForResponse(r=>r.url().endsWith(`/${job.repair_job_id}/reject`));
  await page.getByRole('button',{name:'Reject Repairs',exact:true}).click();
  expect((await rejected).status()).toBe(200);
  await expect(page.getByRole('region',{name:'Deterministic SBOM auto-repair'})).toContainText('Approval: REJECTED');
  expect(hash(await original(page.request,session))).toBe(hash(raw));
  const response = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/approve`),{headers:tenantHeaders});
  expect(response.status()).toBe(409);
  const history = await page.request.get(api(`/api/sbom-validation-sessions/${session}/history`),{headers:tenantHeaders});
  expect((await history.json()).some((e:any)=>e.event_type==='SBOM_REPAIR_REJECTED')).toBe(true);
});

test('partial repair remains failed and acceptance stays disabled without refresh', async ({page}) => {
  await login(page);
  const {session,raw} = await upload(page,partialSbom());
  const job = await createJob(page,session);
  expect(job.status).toBe('PARTIALLY_REPAIRED');
  expect(job.validation_status).toBe('FAILED');
  expect(job.manual_errors).toBeGreaterThan(0);
  await expect(page.getByRole('button',{name:'Accept Repairs',exact:true})).toBeDisabled();
  await expect(page.getByRole('region',{name:'Deterministic SBOM auto-repair'})).toContainText('Validation: FAILED');
  expect(hash(await original(page.request,session))).toBe(hash(raw));
});

test('ambiguous dependency is not guessed or changed', async ({page}) => {
  await login(page);
  const {session,raw} = await upload(page,ambiguousSbom());
  await expect(page.getByRole('region',{name:'Deterministic SBOM auto-repair'})).toContainText('1 have suggested fixes');
  await expect(page.getByRole('button',{name:'Auto-Repair Safe Issues',exact:true})).toHaveCount(0);
  const run = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair`),{headers:tenantHeaders});
  const job = await run.json();
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  await expect(quality).toContainText('manual review');
  expect(job.repairs_applied).toBe(0);
  expect(job.validation_status).toBe('FAILED');
  const candidate = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/download`),{headers:tenantHeaders});
  expect(await candidate.body()).toEqual(raw);
});

for (const role of ['analyst', 'developer', 'viewer']) {
  test(`real ${role} login agrees with repair API permissions and controls`, async ({ page, browser }) => {
    await login(page);
    const { session } = await upload(page, repairableSbom());
    const job = await createJob(page, session);
    const context = await browser.newContext({ baseURL: manifest.origin, ignoreHTTPSErrors: true });
    try {
      const rolePage = await context.newPage();
      await login(rolePage, role);
      await rolePage.goto(`/repair/${session}`);
      const panel = rolePage.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
      await expect(panel).toContainText('REPAIRED');
      const writable = role === 'analyst';
      await expect(panel.getByRole('button', { name: 'Accept Repairs', exact: true })).toHaveCount(writable ? 1 : 0);
      await expect(panel.getByRole('button', { name: 'Reject Repairs', exact: true })).toHaveCount(writable ? 1 : 0);
      await expect(panel.getByRole('button', { name: 'Download Repaired SBOM', exact: true })).toHaveCount(writable ? 1 : 0);
      const root = api(`/api/sbom-validation-sessions/${session}/repair`);
      expect((await rolePage.request.get(`${root}/${job.repair_job_id}`, { headers: tenantHeaders })).status()).toBe(200);
      expect((await rolePage.request.get(`${root}/${job.repair_job_id}/download`, { headers: tenantHeaders })).status()).toBe(writable ? 200 : 403);
      expect((await rolePage.request.post(root, { headers: tenantHeaders })).status()).toBe(writable ? 200 : 403);
      if (writable) {
        await panel.getByRole('button', { name: 'Accept Repairs', exact: true }).click();
        await expect(panel).toContainText('Approval: APPROVED');
      } else {
        for (const action of ['approve', 'reject']) {
          expect((await rolePage.request.post(`${root}/${job.repair_job_id}/${action}`, { headers: tenantHeaders })).status()).toBe(403);
        }
      }
    } finally { await context.close(); }
  });
}

test('real foreign tenant cannot enumerate or mutate any repair surface', async ({ page, browser }) => {
  await login(page);
  const { session } = await upload(page, repairableSbom());
  const job = await createJob(page, session);
  const context = await browser.newContext({ baseURL: manifest.origin, ignoreHTTPSErrors: true });
  try {
    const foreign = await context.newPage();
    await login(foreign, 'foreign');
    const headers = { ...tenantHeaders, 'X-Tenant-ID': String(manifest.tenant_b) };
    const root = api(`/api/sbom-validation-sessions/${session}/repair`);
    for (const suffix of ['', `/${job.repair_job_id}`, `/${job.repair_job_id}/changes`, `/${job.repair_job_id}/download`, `/${job.repair_job_id}/report`]) {
      const response = await foreign.request.get(root + suffix, { headers });
      expect(response.status()).toBe(404);
      const body = await response.text();
      expect(body).not.toContain('Repair Tenant A');
      expect(body).not.toContain(job.repair_job_id);
      expect(body).not.toContain(job.candidate_sha256);
    }
    for (const suffix of ['/analyze', '', `/${job.repair_job_id}/approve`, `/${job.repair_job_id}/reject`]) {
      expect((await foreign.request.post(root + suffix, { headers })).status()).toBe(404);
    }
  } finally { await context.close(); }
});

test('signed SBOM gives manual-review reason and is not rewritten', async ({ page }) => {
  await login(page);
  const signed = { ...repairableSbom(), signature: { algorithm: 'RS256', value: 'abc' } };
  const { session, raw } = await upload(page, signed);
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('Signed');
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await expect(quality).toContainText('/ 100');
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  await expect(quality).not.toContainText('Available for review');
  await expect(panel.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
  const result = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair`), { headers: tenantHeaders });
  const job = await result.json();
  expect(job.repairs_applied).toBe(0);
  expect(job.status).toBe('MANUAL_REVIEW_REQUIRED');
  const candidate = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/download`), { headers: tenantHeaders });
  expect(await candidate.body()).toEqual(raw);
});

test('wrong reviewed hash is rejected and UI can then approve correct candidate', async ({ page }) => {
  await login(page);
  const { session } = await upload(page, repairableSbom());
  const job = await createJob(page, session);
  const result = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/approve`), {
    headers: tenantHeaders, data: { candidate_sha256: '0'.repeat(64) },
  });
  expect(result.status()).toBe(409);
  await page.getByRole('button', { name: 'Accept Repairs', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Deterministic SBOM auto-repair' })).toContainText('Approval: APPROVED');
});

test('repair review controls fit mobile and retain readable dark-theme diffs', async ({ page }) => {
  await login(page);
  await upload(page, repairableSbom());
  // The desktop upload dialog follows the existing application layout.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('Validation: PASSED');
  await panel.getByRole('button', { name: 'View Changes', exact: true }).click();
  await expect(panel).toContainText('Old Value');
  const overflow = await panel.evaluate(el => el.scrollWidth - el.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 1440, height: 900 });
  const theme = page.getByRole('button', { name: 'Switch to dark theme', exact: true });
  if (await theme.isVisible()) await theme.click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await expect(panel).toContainText('New Value');
  expect(await panel.evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
});

test('saved draft edits automatically disable stale approval and enable a new repair', async ({ page }) => {
  await login(page);
  const { session } = await upload(page, repairableSbom());
  const old = await createJob(page, session);
  const edited = repairableSbom();
  edited.components[0].name = 'manually-edited-release-app';
  await page.getByRole('textbox', { name: 'SBOM repair editor', exact: true }).fill(JSON.stringify(edited, null, 2));
  await page.getByRole('button', { name: 'Save changes', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('Source draft changed');
  await expect(panel).toContainText('quality comparison belongs to an earlier draft');
  await expect(panel.getByRole('button', { name: 'Accept Repairs', exact: true })).toBeDisabled();
  const stale = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair/${old.repair_job_id}/approve`), { headers: tenantHeaders });
  expect(stale.status()).toBe(409);
  const fresh = await createJob(page, session);
  expect(fresh.repair_job_id).not.toBe(old.repair_job_id);
  await expect(panel).not.toContainText('Source draft changed');
  await expect(panel.getByRole('button', { name: 'Accept Repairs', exact: true })).toBeEnabled();
});

test('CycloneDX XML retains validation errors and clearly declines automatic repair', async ({ page }) => {
  await login(page);
  const xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="LIBRARY" bom-ref="xml-lib"><name>xml-library</name><version>1</version></component></components></bom>';
  const { session, raw } = await upload(page, xml, false, 'release.cdx.xml');
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('unsupported for this format');
  await expect(panel.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
  expect(await original(page.request, session)).toEqual(raw);
});

test('SPDX JSON unsupported structural repairs remain manual', async ({ page }) => {
  await login(page);
  const spdx = spdxSbom();
  delete spdx.dataLicense;
  const { session, raw } = await upload(page, spdx, false, 'release.spdx.json');
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(page.getByRole('region', { name: 'SBOM Quality', exact: true })).toContainText('SPDX 2.3 JSON');
  await expect(panel.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
  expect(await original(page.request, session)).toEqual(raw);
});

test('Phase 2 valid incomplete upload keeps validation PASS and shows advisory quality', async ({ page }) => {
  await login(page);
  const { session } = await upload(page, validSbom(), true);
  await page.goto(`/repair/${session}`);
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await expect(quality).toContainText('Validation: PASSED');
  await expect(quality).toContainText('/ 100');
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  await expect(quality).toContainText('missing licenses');
  await expect(page.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
  const response = await page.request.get(api(`/api/sbom-validation-sessions/${session}/quality`), { headers: tenantHeaders });
  expect(response.status()).toBe(200);
  const data = await response.json();
  expect(data.assessment.overall_score).toBeLessThan(100);
  expect(data.assessment.validation_status).toBe('PASSED');
});

test('Phase 2 actual candidate quality improves and accepted artifact retains its score', async ({ page }) => {
  await login(page);
  const { session } = await upload(page, repairableSbom());
  const job = await createJob(page, session);
  expect(job.quality.improvement).toBeGreaterThan(0);
  expect(job.quality.before.artifact_hash).toBe(job.source_sha256);
  expect(job.quality.after.artifact_hash).toBe(job.candidate_sha256);
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel.getByRole('group', { name: 'Quality Improvement' })).toBeVisible();
  await expect(panel).toContainText(`Change: +${job.quality.improvement} points`);
  await panel.getByRole('button', { name: 'Accept Repairs', exact: true }).click();
  await expect(panel).toContainText('Approval: APPROVED');
  const approved = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair`), { headers: tenantHeaders });
  const accepted = await approved.json();
  const quality = await page.request.get(api(`/api/sboms/${accepted.imported_sbom_id}/quality`), { headers: tenantHeaders });
  expect(quality.status()).toBe(200);
  const acceptedQuality = (await quality.json()).assessment;
  expect(acceptedQuality.artifact_hash).toBe(job.candidate_sha256);
  expect(acceptedQuality.overall_score).toBe(job.quality.after.overall_score);
  await page.setViewportSize({ width: 768, height: 1024 });
  await expect.poll(() => panel.evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => panel.evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
});

test('Phase 2 missing license has no fabricated deterministic fix', async ({ page }) => {
  await login(page);
  const { session } = await upload(page, validSbom(), true);
  await page.goto(`/repair/${session}`);
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  const finding = quality.locator('article').filter({ hasText: 'missing licenses' }).first();
  await expect(finding).toContainText('Not available — manual review');
  await expect(finding).toContainText('unknown values cannot be invented');
  const analysis = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair/analyze`), { headers: tenantHeaders });
  expect((await analysis.json()).auto_fixable).toBe(0);
});

test('Phase 2 quality snapshots and findings cannot be read by another tenant', async ({ page, browser }) => {
  await login(page);
  const { session, sbomId } = await upload(page, validSbom(), true);
  const context = await browser.newContext({ baseURL: manifest.origin, ignoreHTTPSErrors: true });
  try {
    const foreign = await context.newPage();
    await login(foreign, 'foreign');
    const headers = { ...tenantHeaders, 'X-Tenant-ID': String(manifest.tenant_b) };
    for (const route of [`/api/sbom-validation-sessions/${session}/quality`, `/api/sboms/${sbomId}/quality`]) {
      const response = await foreign.request.get(api(route), { headers });
      expect(response.status()).toBe(404);
      expect(await response.text()).not.toMatch(/overall_score|artifact_hash|QUALITY_LICENSES|dimension_scores/);
    }
  } finally { await context.close(); }
});


function spdxSbom() {
  return JSON.parse(readFileSync('../../tests/fixtures/sboms/valid/spdx_2_3_minimal.json', 'utf8'));
}

test('Phase 3 valid SPDX upload continues native processing with quality', async ({ page }) => {
  await login(page);
  const { session, raw, sbomId } = await upload(page, spdxSbom(), true, 'phase3.spdx.json');
  const response = await page.request.get(api(`/api/sboms/${sbomId}?include_raw=true`), { headers: tenantHeaders });
  expect((await response.json()).sbom_data).toBe(raw.toString());
  await page.goto(`/repair/${session}`);
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await expect(quality).toContainText('SPDX 2.3 JSON');
  await expect(quality).toContainText('Validation: PASSED');
  await expect(quality).toContainText('Relationship Integrity');
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  await expect(quality).toContainText('/packages/0/checksums');
  expect(await original(page.request, session)).toEqual(raw);
});

test('Phase 3 SPDX native repair shows actual quality gain and approves SPDX bytes', async ({ page }) => {
  await login(page);
  const doc = spdxSbom();
  doc.relationships[0].relatedSpdxElement = 'pkg:npm/foo@1.0.0';
  doc.packages[0].externalRefs[0].referenceLocator = ' pkg:npm/foo@1.0.0 ';
  const { session, raw } = await upload(page, doc, false, 'phase3-repair.spdx.json');
  const job = await createJob(page, session);
  expect(job.format).toBe('SPDX_JSON');
  expect(job.status).toBe('REPAIRED');
  expect(job.quality.improvement).toBeGreaterThan(0);
  await page.getByRole('button', { name: 'View Changes', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('spdx_reference');
  await expect(panel).toContainText('referenceLocator');
  await expect(page.getByRole('group', { name: 'Quality Improvement' })).toContainText('Before:');
  const approved = page.waitForResponse(r => r.url().endsWith(`/${job.repair_job_id}/approve`));
  await panel.getByRole('button', { name: 'Accept Repairs', exact: true }).click();
  expect((await approved).status()).toBe(200);
  await expect(panel).toContainText('Approval: APPROVED');
  const link = panel.getByRole('link', { name: 'Open Accepted SBOM', exact: true });
  const id = Number((await link.getAttribute('href'))!.split('/').pop());
  const accepted = await page.request.get(api(`/api/sboms/${id}?include_raw=true`), { headers: tenantHeaders });
  const content = JSON.parse((await accepted.json()).sbom_data);
  expect(content.spdxVersion).toBe('SPDX-2.3');
  expect(content.bomFormat).toBeUndefined();
  expect(await original(page.request, session)).toEqual(raw);
});

test('Phase 3 duplicate SPDX relationships repair without replacing inverse forms', async ({ page }) => {
  await login(page);
  const doc = spdxSbom();
  doc.relationships.push({ ...doc.relationships[0] });
  const { session } = await upload(page, doc, true, 'phase3-duplicate.spdx.json');
  await page.goto(`/repair/${session}`);
  const job = await createJob(page, session);
  expect(job.status).toBe('REPAIRED');
  const candidate = await page.request.get(api(`/api/sbom-validation-sessions/${session}/repair/${job.repair_job_id}/download`), { headers: tenantHeaders });
  expect((await candidate.json()).relationships).toHaveLength(1);
});

test('Phase 3 ambiguous SPDX relationship stays manual', async ({ page }) => {
  await login(page);
  const doc = spdxSbom();
  doc.packages.push({ ...doc.packages[0], SPDXID: 'SPDXRef-other', supplier: 'Organization: Other' });
  doc.relationships[0].relatedSpdxElement = 'pkg:npm/foo@1.0.0';
  const { session, raw } = await upload(page, doc, false, 'phase3-ambiguous.spdx.json');
  const panel = page.getByRole('region', { name: 'Deterministic SBOM auto-repair' });
  await expect(panel).toContainText('require manual review');
  await expect(panel.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
  expect(await original(page.request, session)).toEqual(raw);
});

test('Phase 3 NOASSERTION is a manual quality finding and no license is invented', async ({ page }) => {
  await login(page);
  const doc = spdxSbom();
  doc.packages[0].licenseDeclared = doc.packages[0].licenseConcluded = 'NOASSERTION';
  const { session } = await upload(page, doc, true, 'phase3-license.spdx.json');
  await page.goto(`/repair/${session}`);
  const quality = page.getByRole('region', { name: 'SBOM Quality', exact: true });
  await quality.getByRole('button', { name: 'View Quality Findings' }).click();
  await expect(quality).toContainText('NOASSERTION');
  await expect(quality).toContainText('Not available — manual review');
  await expect(page.getByRole('button', { name: 'Auto-Repair Safe Issues', exact: true })).toHaveCount(0);
});

test('Phase 3 SPDX quality and candidate remain tenant scoped', async ({ page }) => {
  await login(page);
  const doc = spdxSbom();
  doc.relationships[0].relatedSpdxElement = 'pkg:npm/foo@1.0.0';
  const { session } = await upload(page, doc, false, 'phase3-tenant.spdx.json');
  const job = await createJob(page, session);
  const foreignHeaders = { ...tenantHeaders, 'X-Tenant-ID': String(manifest.tenant_b) };
  for (const suffix of ['quality', `repair/${job.repair_job_id}`, `repair/${job.repair_job_id}/download`]) {
    const response = await page.request.get(api(`/api/sbom-validation-sessions/${session}/${suffix}`), { headers: foreignHeaders });
    expect(response.status()).toBe(404);
    const text = await response.text();
    expect(text).not.toContain('SPDXRef');
    expect(text).not.toContain('overall_score');
  }
});

for (const [name, text, mimeType] of [
  ['SPDX YAML', 'spdxVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nname: unsupported-format\n', 'application/yaml'],
  ['SPDX 3 JSON-LD', JSON.stringify({'@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', type: 'SpdxDocument'}), 'application/ld+json'],
]) {
  test(`unsupported ${name} offers no quality or automatic repair`, async ({page}) => {
    await login(page);
    const response = await page.request.post(api('/api/sboms/upload'), {
      headers: tenantHeaders,
      multipart: {
        file: {name: name.includes('YAML') ? 'unsupported.spdx.yaml' : 'unsupported.spdx.json', mimeType, buffer: Buffer.from(text)},
        sbom_name: `unsupported-${randomUUID()}`,
        project_id: String(manifest.project_id), product_id: String(manifest.product_id),
      },
    });
    expect(name.includes('YAML') ? [422] : [400, 415]).toContain(response.status());
    const body = await response.json();
    expect(JSON.stringify(body)).toMatch(name.includes('YAML') ? /SBOM_VAL_E014_SPEC_VERSION_MISSING/ : /SBOM_VAL_E010_FORMAT_INDETERMINATE|SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED/);
    const session = body.detail?.validation_session_id;
    if (session) {
      await page.goto(`/sboms/repair/${session}`);
      const quality = await page.request.get(api(`/api/sbom-validation-sessions/${session}/quality`), {headers: tenantHeaders});
      expect(quality.status()).toBe(200);
      expect((await quality.json()).assessment.supported).toBe(false);
      const analysis = await page.request.post(api(`/api/sbom-validation-sessions/${session}/repair/analyze`), {headers: tenantHeaders});
      expect(analysis.status()).toBe(200);
      expect((await analysis.json()).repair_supported).toBe(false);
    }
    await expect(page.getByRole('button', {name:'Auto-Repair Safe Issues', exact:true})).toHaveCount(0);
  });
}
