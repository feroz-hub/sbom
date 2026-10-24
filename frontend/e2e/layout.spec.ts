/** Read-only layout checks. Existing fixture credentials stay in memory. */
import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

type TestUser = { email: string; password: string };
const users: Record<string, TestUser> = JSON.parse(readFileSync(process.env.LAYOUT_E2E_USERS_FILE!, 'utf8'));

// Some existing pages repeat h1 inside their settings panel. The first h1
// is the route title shared by the surrounding content layout.
const pageTitle = (page: Page) => page.locator('#main-content h1').first();

async function login(page: Page, role: 'admin' | 'platform' = 'admin') {
  await page.goto('/native-sign-in');
  await page.getByLabel('Email address').fill(users[role].email);
  await page.getByLabel('Password', { exact: true }).fill(users[role].password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const header = page.getByLabel('Authenticated application header');
  const selection = page.getByRole('heading', { name: 'Select tenant', exact: true });
  await expect(header.or(selection)).toBeVisible({ timeout: 120_000 });
  if (await selection.isVisible()) {
    await page.getByRole('button', { name: 'Olympus Tenant Admin', exact: true }).click();
  }
  await expect(header).toBeVisible();
  await expect(pageTitle(page)).toBeVisible();
}

async function assertRegions(page: Page) {
  await expect(page.getByLabel('Authenticated application header')).toBeVisible();
  await expect(page.locator('#main-content')).toHaveCSS('overflow-y', 'auto');
  const geometry = await page.evaluate(() => {
    const header = document.querySelector<HTMLElement>('header[aria-label="Authenticated application header"]')!;
    const main = document.getElementById('main-content')!;
    const banner = document.querySelector<HTMLElement>('[aria-label="AI batch progress"]');
    const h = header.getBoundingClientRect();
    const m = main.getBoundingClientRect();
    return {
      headerTop: h.top,
      mainTop: m.top,
      expectedMainTop: banner?.getBoundingClientRect().bottom ?? h.bottom,
      mainBottom: m.bottom,
      viewportHeight: innerHeight,
      documentScroll: window.scrollY,
      documentHeight: document.documentElement.scrollHeight,
      headerInsideMain: main.contains(header),
      overflow: getComputedStyle(main).overflowY,
      headerHit: header.contains(document.elementFromPoint(h.right - 8, h.bottom - 1)),
    };
  });
  expect(geometry.headerTop).toBe(0);
  expect(geometry.headerInsideMain).toBe(false);
  expect(geometry.mainTop).toBeCloseTo(geometry.expectedMainTop, 0);
  expect(geometry.mainBottom).toBe(geometry.viewportHeight);
  expect(geometry.documentScroll).toBe(0);
  expect(geometry.documentHeight, 'The document must not acquire a second scrollbar').toBe(geometry.viewportHeight);
  expect(geometry.overflow).toBe('auto');
  expect(geometry.headerHit).toBe(true);
}

async function assertScroll(page: Page) {
  await assertRegions(page);
  const main = page.locator('#main-content');
  const previousAnchor = await main.evaluate(el => el.style.overflowAnchor);
  // Query results can settle while wheel input is being delivered. Keep the
  // temporary fixture's scroll position independent of those layout shifts.
  await main.evaluate(el => { el.style.overflowAnchor = 'none'; });
  // Short/empty pages need deterministic overflow too. This browser-only
  // fixture exercises the real route, shell, sticky title and clipping rules.
  await page.locator('#main-content > div').evaluate(container => {
    const notice = document.createElement('p');
    notice.dataset.layoutFixture = 'true';
    notice.setAttribute('role', 'alert');
    notice.style.cssText = 'padding:16px;flex-shrink:0';
    notice.textContent = 'Layout regression notification';
    container.prepend(notice);
    const fixture = document.createElement('section');
    fixture.dataset.layoutFixture = 'true';
    fixture.style.cssText = 'height:1800px;flex-shrink:0;padding:16px';
    fixture.innerHTML = '<p style="margin-top:1700px">End of scroll fixture</p>';
    container.append(fixture);
  });
  await main.evaluate(el => { el.scrollTop = 0; });
  await page.getByText('Layout regression notification', { exact: true }).hover();
  await page.mouse.wheel(0, 600);
  await expect.poll(() => main.evaluate(el => el.scrollTop)).toBe(600);
  await assertRegions(page);
  const titlePosition = await pageTitle(page).evaluate(heading => heading.getBoundingClientRect().bottom);
  const contentTop = await main.evaluate(el => el.getBoundingClientRect().top);
  expect(titlePosition, 'Page titles must scroll with the content instead of covering alerts').toBeLessThanOrEqual(contentTop);
  // Wheel input at the sidebar must not move the content scrollport.
  if (page.viewportSize()!.width >= 768) {
    const contentScroll = await main.evaluate(el => el.scrollTop);
    const sidebar = page.locator('.app-sidebar-scroll');
    await sidebar.hover();
    await page.mouse.wheel(0, 600);
    if (await sidebar.evaluate(el => el.scrollHeight > el.clientHeight)) {
      await expect.poll(() => sidebar.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
    }
    await expect(main).toHaveJSProperty('scrollTop', contentScroll);
  }
  await main.evaluate(el => { el.scrollTop = 0; });
  await expect(page.getByText('Layout regression notification', { exact: true })).toBeVisible();
  await page.locator('[data-layout-fixture]').evaluateAll(elements => elements.forEach(el => el.remove()));
  await main.evaluate((el, anchor) => { el.style.overflowAnchor = anchor; }, previousAnchor);
}

const tenantRoutes = [
  '/', '/projects', '/sboms', '/analysis?tab=runs', '/analysis?tab=consolidated', '/analysis?tab=vulnerabilities',
  '/analysis/compare', '/kev', '/vex-investigation', '/component-advisor', '/schedules',
  '/settings', '/settings/users', '/settings/native-users', '/settings/users/audit', '/settings/tenant',
  '/settings/ai', '/settings/advisor-policies', '/settings/notifications',
  '/admin/lifecycle-providers', '/admin/lifecycle-vendor-records', '/admin/ai-usage',
  '/docs/sbom-validation-errors',
];

test('authenticated header sits outside the page scrollport', async ({ page }) => {
  await login(page, 'platform');
  await assertRegions(page);
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  test(`tenant routes keep content below the header at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await login(page);
    for (const route of tenantRoutes) {
      await test.step(route, async () => {
        console.info(`[layout ${viewport.width}px] ${route}`);
        await page.goto(route, { waitUntil: 'domcontentloaded' });
        await expect(pageTitle(page)).toBeVisible();
        await assertScroll(page);
        if (route === '/') {
          await expect(page.getByText('Updating dashboard…', { exact: true })).toHaveCount(0);
          await page.locator('#main-content').evaluate(el => { el.scrollTop = 300; });
          await page.locator('.app-sidebar-scroll').evaluate(el => { el.scrollTop = 0; });
          await page.screenshot({ path: test.info().outputPath(`dashboard-${viewport.width}.png`) });
        }
      });
    }
  });
}

test('platform administration uses the same scroll regions', async ({ page }) => {
  await login(page, 'platform');
  for (const route of [
    '/platform', '/settings/platform/tenants', '/settings/platform', '/settings/iam',
    '/platform/configuration/ai', '/platform/configuration/lifecycle',
    '/platform/configuration/advisor-policies',
  ]) {
    await test.step(route, async () => {
      await page.goto(route);
      await expect(pageTitle(page)).toBeVisible();
      await assertScroll(page);
    });
  }
});

test('laptop, tablet and mobile landscape retain the available viewport', async ({ page }) => {
  await login(page);
  for (const viewport of [
    { width: 1366, height: 768 }, { width: 768, height: 1024 },
    { width: 844, height: 390 }, { width: 320, height: 568 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('/settings/users');
    await assertScroll(page);
  }
});

test('sidebar collapse, navigation, skip link and mobile drawer preserve scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await login(page);
  await page.getByRole('button', { name: 'Collapse sidebar', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Expand sidebar', exact: true })).toBeVisible();
  await assertScroll(page);
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
  await expect(page.locator('#main-content')).toHaveJSProperty('scrollTop', 0);
  await page.getByRole('link', { name: 'Skip to main content', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
  await assertRegions(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await expect(page.locator('#main-content')).toHaveCSS('overflow-y', 'hidden');
  await page.getByRole('link', { name: 'SBOMs', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'SBOMs', exact: true })).toBeVisible();
  await assertScroll(page);
});

test('opening a dialog locks the new background scrollport', async ({ page }) => {
  await login(page);
  await page.goto('/projects');
  await page.getByRole('button', { name: 'New Project', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  // Closed sibling dialogs can clear this shared flag after a query refresh.
  // The visible modal must still lock the application's scrollports.
  await page.evaluate(() => { delete document.body.dataset.dialogOpen; });
  await expect(page.locator('#main-content')).toHaveCSS('overflow-y', 'hidden');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await assertScroll(page);
});

test('a changing global progress row reserves its height above scrolling content', async ({ page }) => {
  await login(page, 'platform');
  await page.getByLabel('Authenticated application header').evaluate(header => {
    const banner = document.createElement('div');
    banner.setAttribute('aria-label', 'AI batch progress');
    banner.dataset.layoutFixture = 'true';
    banner.style.height = '48px';
    banner.textContent = 'Layout progress fixture';
    header.nextElementSibling!.append(banner);
  });
  await assertRegions(page);
  await page.getByLabel('AI batch progress').evaluate(banner => { banner.style.height = '128px'; });
  await assertScroll(page);
  await assertRegions(page);
});

test('existing SBOM history, findings and report controls stay within the content region', async ({ page }) => {
  await login(page);
  await page.goto('/sboms');
  // Discover actual record routes from rendered links; never create test data.
  await expect(page.locator('#main-content a[href^="/sboms/"]').first()).toBeVisible();
  const routes = await page.locator('#main-content a[href]').evaluateAll(links => [...new Set(
    links.map(link => link.getAttribute('href')!).filter(href => /^\/sboms\/(?:logical\/)?[0-9a-f-]+$/i.test(href)),
  )]);
  expect(routes.length, 'Existing SBOM fixtures are required for detail-page coverage').toBeGreaterThan(0);
  const detail = routes.find(route => !route.includes('/logical/'))!;
  await page.goto(detail);
  await expect(pageTitle(page)).toBeVisible();
  await assertScroll(page);
  for (const name of ['Components List', 'Analysis Runs']) {
    await page.getByRole('button', { name, exact: true }).click();
    await assertScroll(page);
  }
  await page.goto('/analysis?tab=runs');
  const runRows = page.getByRole('table', { name: 'Analysis runs table' }).getByRole('row')
    .filter({ has: page.getByRole('checkbox', { name: /^Select Run/ }) });
  await expect(runRows.first()).toBeVisible();
  // The table opens records by row click. Use its SBOM cell after the
  // comparison checkbox and run ID, avoiding pin/status action buttons.
  await runRows.first().getByRole('cell').nth(2).click();
  await page.waitForURL(/\/analysis\/[0-9a-f-]+$/i);
  await expect(pageTitle(page)).toBeVisible();
  await assertScroll(page);
  await page.getByRole('button', { name: 'Export', exact: true }).click();
  const exports = page.getByRole('menu', { name: 'Export', exact: true });
  await expect(exports.getByText('PDF report', { exact: true })).toBeVisible();
  await expect(exports.getByText('CSV', { exact: true })).toBeVisible();
  await expect(exports.getByText('SARIF', { exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  const history = routes.find(route => route.includes('/logical/'));
  if (history) {
    await page.goto(history);
    await expect(pageTitle(page)).toBeVisible();
    await assertScroll(page);
  }
});
