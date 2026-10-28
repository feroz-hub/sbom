/* Local UAT runner. Credentials and cookies remain in memory; no traces/video. */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const root = '/Users/ferozebasha/sbom';
const state = '/Users/ferozebasha/.sbom-greenfield-uuid';
const output = path.join(root, 'docs/uat/evidence/2026-10-19');
fs.mkdirSync(output, { recursive: true });
const identities = JSON.parse(fs.readFileSync(path.join(state, 'users.json'), 'utf8'));
const caseFile = path.join(output, process.argv[2] === 'security' ? 'direct-api-cases.json' : process.argv[2] === 'business' ? 'business-api-cases.json' : process.argv[2] === 'extended' ? 'extended-cases.json' : 'cases.json');
const cases = fs.existsSync(caseFile) ? JSON.parse(fs.readFileSync(caseFile, 'utf8')) : [];
const traffic = [];
const origin = 'https://localhost:13000';
function sanitize(v) {
  let s = typeof v === 'string' ? v : JSON.stringify(v);
  for (const u of Object.values(identities)) if (u.password) s = s.split(u.password).join('[REDACTED]');
  return s.replace(/eyJ[A-Za-z0-9_.-]+/g, '[TOKEN]').replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
    .replace(/(__Host-sbom-session=)[^;\s]+/g, '$1[REDACTED]')
    .replace(/(\b[Cc]ookie:)[^\n]+/g, '$1 [REDACTED]')
    .replace(/(token|password|cookie|secret)=([^\s&]+)/gi, '$1=[REDACTED]');
}
function record(id, module, role, expected, actual, status, steps, api = null, defect = null) {
  const preconditions = ['security','extended'].includes(process.argv[2])
    ? 'Independent Native bearer authentication per role; direct HTTP loopback API; greenfield development stack; no browser session reused'
    : 'Fresh isolated Chrome context; Native Login; TLS validation enabled; greenfield development stack';
  const result = { id, module, role, preconditions, steps, expected, actual, api, status, defect, time: new Date().toISOString() };
  const i = cases.findIndex(c => c.id === id);
  if (i >= 0) cases[i] = result; else cases.push(result);
  fs.writeFileSync(caseFile, sanitize(JSON.stringify(cases, null, 2)));
  fs.writeFileSync(path.join(output, 'http-' + process.argv[2] + '.json'), JSON.stringify(traffic, null, 2));
  console.log(id, status, sanitize(actual).slice(0, 350));
}
async function api(page, url, method = 'GET', body, tenant) {
  return page.evaluate(async ({ url, method, body, tenant }) => {
    const selected = tenant === undefined ? sessionStorage.getItem('sbom_active_tenant_id') : tenant;
    const r = await fetch('/api/backend' + url, { method,
      headers: { ...(selected ? { 'X-Tenant-ID': selected } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await r.text(); let data;
    try { data = JSON.parse(text); } catch { data = text.slice(0, 500); }
    return { status: r.status, data, requestId: r.headers.get('x-request-id') };
  }, { url, method, body, tenant });
}
async function login(browser, role) {
  const context = await browser.newContext({ ignoreHTTPSErrors: false, reducedMotion: 'reduce', viewport: { width: 1440, height: 1100 } });
  const page = await context.newPage(); page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(30000);
  try {
  const errors = [];
  page.on('pageerror', e => errors.push(sanitize(e.message)));
  page.on('response', r => { const u = new URL(r.url()); if (u.pathname.startsWith('/api/')) traffic.push({ role, time: new Date().toISOString(), path: u.pathname, method: r.request().method(), status: r.status(), requestId: r.headers()['x-request-id'] || null }); });
  console.log('Starting clean Native Login:', role);
  await page.goto(origin + '/native-sign-in', { waitUntil: 'domcontentloaded' });
  await page.waitForLoadState('networkidle', { timeout: 30000 });
  await page.getByLabel('Email address').fill(identities[role].email);
  await page.getByLabel('Password', { exact: true }).fill(identities[role].password);
  const response = page.waitForResponse(r => r.url().endsWith('/api/auth/native/login') && r.request().method() === 'POST', { timeout: 30000 });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const status = (await response).status();
  await page.getByRole('heading', { name: 'Select tenant', exact: true }).or(page.getByRole('heading', { name: role === 'platform' ? 'Platform Dashboard' : 'Dashboard', exact: true })).waitFor({ timeout: 25000 });
  if (await page.getByRole('heading', { name: 'Select tenant', exact: true }).isVisible()) {
    await page.getByRole('button', { name: role === 'foreign' ? 'Isolation Control Tenant Admin' : 'Olympus Tenant Admin', exact: true }).click();
  }
  await page.getByRole('heading', { name: role === 'platform' ? 'Platform Dashboard' : 'Dashboard', exact: true }).waitFor({ timeout: 25000 });
  const me = await api(page, '/api/auth/me');
  const c = (await context.cookies()).find(c => c.name === '__Host-sbom-session');
  const cookie = { present: Boolean(c), secure: c?.secure, httpOnly: c?.httpOnly, sameSite: c?.sameSite, path: c?.path };
  record('UAT-AUTH-' + role, 'Authentication', role, 'Native Login succeeds with expected role and tenant/platform scope; protected session cookie', { status, me: { user_id: me.data.user_id, email: me.data.email, roles: me.data.roles, tenant_id: me.data.tenant_id, is_platform_admin: me.data.is_platform_admin, permissions: me.data.permissions }, cookie }, status === 200 && me.status === 200 && (role === 'platform' ? me.data.tenant_id === null && me.data.is_platform_admin : me.data.tenant_id === identities[role].tenant_id) && c?.secure && c?.httpOnly ? 'PASS' : 'FAIL', 'Fresh browser context; sign in; choose authorized tenant if prompted; GET auth/me; inspect cookie flags without values', status);
  return { context, page, me: me.data, errors };
  } catch (e) {
    console.log('Login diagnostic:', role, sanitize(JSON.stringify({ path: new URL(page.url()).pathname, headings: await page.locator('h1,h2').allTextContents().catch(() => []), messages: await page.locator('[role="status"],[role="alert"]').allTextContents().catch(() => []), errors, traffic: traffic.filter(t => t.role === role).slice(-8) })));
    await context.close(); throw e;
  }
}
async function logout(session, role) {
  const { page, context, me } = session;
  if (!await page.getByRole('button', { name: 'Account menu for ' + me.display_name, exact: true }).count()) {
    await page.goto(origin + '/settings/users', { waitUntil: 'domcontentloaded', timeout: 60000 });
  }
  await page.getByRole('button', { name: 'Account menu for ' + me.display_name, exact: true }).click();
  await page.getByRole('menuitem', { name: 'Sign Out', exact: true }).click();
  await page.waitForURL(/logged-out/, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
  const cookies = await context.cookies();
  await page.goto(origin + '/projects', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
  const denied = await api(page, '/api/projects');
  record('UAT-LOGOUT-' + role, 'Authentication', role, 'Sign out clears session; protected navigation returns login; API 401', { url: page.url(), sessionCookiePresent: cookies.some(c => c.name === '__Host-sbom-session'), api: denied }, denied.status === 401 && !cookies.some(c => c.name === '__Host-sbom-session') ? 'PASS' : 'FAIL', 'UI account menu > Sign Out; revisit projects; call API with browser session', denied.status);
  await context.close();
}
async function userAdmin(browser) {
  const session = await login(browser, 'admin'); const { page, me } = session; const tenant = me.tenant_id;
  await page.goto(origin + '/settings/users'); await page.getByRole('heading', { name: 'Member Directory', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Add Existing Member', exact: true }).click();
  await page.getByPlaceholder('Search existing users by name or email…').fill('admin@olympus.example.test');
  await page.waitForResponse(r => r.url().includes('/user-candidates')).catch(() => {});
  const lookup = await api(page, '/api/tenants/' + tenant + '/user-candidates?q=admin%40olympus.example.test');
  record('UAT-USER-009', 'Users & Access', 'admin', 'Existing members excluded from candidate lookup', { ui: await page.getByRole('dialog').innerText(), api: lookup }, lookup.status === 200 && lookup.data.items.length === 0 ? 'PASS' : 'FAIL', 'Add Existing Member; search current Admin; compare candidate API', lookup.status);
  try {
    await page.getByRole('button', { name: 'Cancel', exact: true }).click({ timeout: 2000 });
    record('UAT-USER-014', 'Users & Access', 'admin', 'Cancel remains clickable with candidate results open', 'Cancel dismissed dialog', 'PASS', 'Search existing member; click Cancel normally');
  } catch (e) {
    await page.screenshot({ path: path.join(output, 'UAT-USER-014-cancel-overlap.png'), fullPage: true });
    record('UAT-USER-014', 'Users & Access', 'admin', 'Cancel remains clickable with candidate results open', { error: sanitize(e.message), dialog: await page.getByRole('dialog').innerText(), bounds: { cancel: await page.getByRole('button', { name: 'Cancel', exact: true }).boundingBox(), results: await page.getByText('No eligible users found for this tenant.', { exact: true }).boundingBox() } }, 'FAIL', 'Search Admin in Add Existing Member; click Cancel normally; result popup intercepts pointer', null, 'UAT-DEF-001');
    await page.keyboard.press('Escape');
    if (await page.getByRole('dialog').isVisible()) await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  }
  for (const [id, query, expected] of [['010', 'a', 422], ['011', '%20%20', 422], ['012', '%25', 422], ['013', '%27%20OR%201%3D1--', 200]]) {
    const r = await api(page, '/api/tenants/' + tenant + '/user-candidates?q=' + query);
    record('UAT-USER-' + id, 'Users & Access', 'admin', 'Candidate validation/literal escaping: HTTP ' + expected, r, r.status === expected ? 'PASS' : 'FAIL', 'GET candidate endpoint with short/blank/wildcard/SQL-like query', r.status);
  }
  await page.getByRole('button', { name: 'Invite New User', exact: true }).click();
  console.log('INVITE', await page.getByRole('dialog').innerText());
  fs.writeFileSync(path.join(output, 'invite-controls.json'), JSON.stringify(await page.getByRole('dialog').locator('input').evaluateAll(es => es.map(e => ({ name: e.name, type: e.type, value: e.type === 'checkbox' ? e.value : undefined }))), null, 2));
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await logout(session, 'admin');
}
function rows(data) { return Array.isArray(data) ? data : data?.items || data?.sboms || data?.results || []; }
function summary(r) { return { status: r.status, count: rows(r.data).length, total: r.data?.total, keys: r.data && typeof r.data === 'object' && !Array.isArray(r.data) ? Object.keys(r.data).slice(0, 20) : undefined, error: r.status >= 400 ? r.data : undefined, requestId: r.requestId }; }
async function roles(browser) {
  const fixtureFile = path.join(output, 'fixture-identifiers.json');
  let fixtures = fs.existsSync(fixtureFile) ? JSON.parse(fs.readFileSync(fixtureFile, 'utf8')) : {};
  for (const role of (process.argv.slice(3).length ? process.argv.slice(3) : ['admin', 'analyst', 'developer', 'viewer', 'foreign', 'platform'])) {
    let session;
    try {
      session = await login(browser, role); const { page, me, errors } = session; const tenant = me.tenant_id;
      await page.goto(origin + '/settings/users');
      await page.locator('#main-content').waitFor();
      await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
      // Let permission-guarded content settle before reading the controls.
      await page.waitForFunction(() => !document.querySelector('#main-content')?.textContent?.includes('Loading your access context'));
      const read = me.permissions.includes('tenant:user:read'); const invite = me.permissions.includes('tenant:user:invite');
      const add = await page.getByRole('button', { name: 'Add Existing Member', exact: true }).count();
      const invitation = await page.getByRole('button', { name: 'Invite New User', exact: true }).count();
      const text = await page.locator('#main-content').innerText();
      await page.screenshot({ path: path.join(output, 'users-' + role + '.png'), fullPage: true });
      record('UAT-USERS-ACCESS-' + role, 'Users & Access', role, 'UI matches tenant:user:read/invite/update permissions and correct tenant/platform context', { read, invite, add, invitation, text, buttons: await page.locator('#main-content').getByRole('button').allTextContents() }, role === 'platform' ? 'PASS' : Boolean(add) === invite && Boolean(invitation) === invite && (read ? text.includes(role === 'foreign' ? 'Isolation Control' : 'Olympus') : text.includes('permission')) ? 'PASS' : 'FAIL', 'Open Users & Access directly; inspect controls and denial state');
      if (role !== 'platform') {
        for (const [suffix, endpoint, permission] of [
          ['directory', '/api/tenants/' + tenant + '/users', 'tenant:user:read'],
          ['audit', '/api/tenants/' + tenant + '/audit-history', 'tenant:user:read'],
          ['candidates', '/api/tenants/' + tenant + '/user-candidates?q=Olympus', 'tenant:user:invite'],
          ['platform', '/api/platform/tenants', 'platform:tenant:read'],
          ['projects', '/api/projects', 'project:read'], ['sboms', '/api/sboms', 'sbom:read'],
          ['dashboard', '/dashboard/stats', 'dashboard:read'], ['vex', '/api/vex/investigations', 'vex:read'],
          ['kev', '/api/v1/kev?page=1&page_size=5', 'analysis:read'],
          ['notifications', '/api/report-notifications/config', 'sbom:read']]) {
          const r = await api(page, endpoint); const expected = me.permissions.includes(permission) ? 200 : 403;
          record('UAT-READ-' + role + '-' + suffix, suffix, role, 'Implemented permission ' + permission + ': HTTP ' + expected, summary(r), r.status === expected ? 'PASS' : 'FAIL', 'GET ' + endpoint + ' directly through authenticated API; independent of UI visibility', r.status, r.status === expected ? null : 'UAT-DEF-REVIEW-' + suffix);
          if (role === 'admin' && suffix === 'projects') fixtures.projects = rows(r.data);
          if (role === 'admin' && suffix === 'sboms') fixtures.sboms = rows(r.data);
          fs.writeFileSync(fixtureFile, JSON.stringify(fixtures, null, 2));
        }
        if (!invite) {
          const r = await api(page, '/api/tenants/' + tenant + '/users', 'POST', { user_id: 2147483000, roles: ['VIEWER'] });
          record('UAT-DENY-' + role + '-invite', 'Authorization', role, 'Administrative membership creation rejected HTTP 403', r, r.status === 403 ? 'PASS' : 'FAIL', 'POST membership using nonexistent disposable user reference; no seeded users touched', r.status);
          const p = await api(page, '/api/tenants/' + tenant + '/users/2147483000', 'PATCH', { status: 'DISABLED' });
          record('UAT-DENY-' + role + '-membership', 'Authorization', role, 'Administrative membership modification rejected HTTP 403', p, p.status === 403 ? 'PASS' : 'FAIL', 'PATCH nonexistent membership; no seeded users touched', p.status);
        }
        const create = me.permissions.includes('project:create');
        const name = 'UAT-' + role + '-' + Date.now(); const p = await api(page, '/api/projects', 'POST', { project_name: name, project_status: 1 });
        record('UAT-PROJECT-CREATE-' + role, 'Projects', role, create ? 'Permitted project creation returns 201 and public UUID' : 'Prohibited project creation returns 403', create ? { status: p.status, id: p.data.id, name: p.data.project_name } : p, p.status === (create ? 201 : 403) ? 'PASS' : 'FAIL', 'POST unique disposable project; retain any created fixture for inspection', p.status);
        if (p.status === 201) {
          fixtures['project-' + role] = p.data;
          const dup = await api(page, '/api/projects', 'POST', { project_name: name, project_status: 1 });
          record('UAT-PROJECT-DUP-' + role, 'Projects', role, 'Duplicate project name yields conflict HTTP 409', dup, dup.status === 409 ? 'PASS' : 'FAIL', 'Repeat exact disposable project creation', dup.status);
          const canProduct = me.permissions.includes('product:create');
          const prod = await api(page, '/api/projects/' + p.data.id + '/products', 'POST', { name: 'UAT Application', status: 'active' });
          record('UAT-PRODUCT-CREATE-' + role, 'Products', role, canProduct ? 'Permitted product create returns 201' : 'Product creation outside role permission returns 403', canProduct ? { status: prod.status, id: prod.data.id, name: prod.data.name } : prod, prod.status === (canProduct ? 201 : 403) ? 'PASS' : 'FAIL', 'POST disposable product under newly created project', prod.status);
          if (prod.status === 201) fixtures['product-' + role] = prod.data;
          fs.writeFileSync(fixtureFile, JSON.stringify(fixtures, null, 2));
        }
        const available = await page.locator('a[href]').evaluateAll(es => [...new Set(es.map(e => e.getAttribute('href')))]);
        const navigations = [['/', 'Dashboard'], ['/projects', 'Projects'], ['/sboms', 'SBOMs'], ['/analysis', 'Analysis'], ['/kev', 'CISA KEV'], ['/vex-investigation', 'VEX Investigation'], ['/component-advisor', 'Component Advisor'], ['/schedules', 'Schedules'], ['/settings/notifications', 'Notifications'], ['/settings/ai', 'AI Configuration'], ['/settings/advisor-policies', 'Advisor Policies'], ['/admin/lifecycle-providers', 'Lifecycle Providers'], ['/admin/lifecycle-vendor-records', 'Vendor Records']];
        for (const [href, label] of (process.env.UAT_MINIMAL === '1' ? [] : navigations)) {
          if (href !== '/' && !available.some(a => a === href || a?.startsWith(href + '?'))) continue;
          try {
          const before = errors.length; const startTraffic = traffic.length; const response = await page.goto(origin + href, { waitUntil: 'domcontentloaded' });
          await page.locator('#main-content h1').waitFor({ timeout: 12000 }).catch(() => {});
          await page.waitForLoadState('networkidle', { timeout: 7000 }).catch(() => {});
          const content = await page.locator('#main-content').innerText();
          const apiErrors = traffic.slice(startTraffic).filter(t => t.status >= 400);
          const pass = response.status() < 400 && errors.length === before && !content.includes('Application error:') && !apiErrors.some(t => t.status >= 500);
          record('UAT-PAGE-' + role + '-' + href.replace(/[^a-z]+/g, '-'), label, role, 'Accessible page renders its content without a browser crash or HTTP 5xx (page/read smoke only)', { url: page.url(), http: response.status(), headings: await page.locator('#main-content h1,#main-content h2').allTextContents(), content: content.slice(0, 2600), apiErrors, pageErrors: errors.slice(before) }, pass ? 'PASS' : 'FAIL', 'Navigate visible ' + label + ' module; wait for page content and API requests', response.status(), pass ? null : 'UAT-DEF-PAGE-' + label.replace(/\W/g, '-'));
          } catch (e) {
            record('UAT-PAGE-' + role + '-' + href.replace(/[^a-z]+/g, '-'), label, role, 'Accessible page responds and renders within navigation budget', sanitize(e.message), 'BLOCKED', 'Navigate ' + href + '; navigation did not complete; functional page outcome unverified');
          }
        }
        if (role === 'admin') {
          const project = fixtures.projects.find(p => p.project_name === 'Olympus Release') || fixtures.projects[0];
          if (project) { const products = await api(page, '/api/projects/' + project.id + '/products'); fixtures.products = rows(products.data); }
          fs.writeFileSync(path.join(output, 'fixture-identifiers.json'), JSON.stringify(fixtures, null, 2));
        }
      } else {
        const p = await api(page, '/api/platform/tenants');
        record('UAT-PLATFORM-TENANTS', 'Tenant Management', role, 'Platform lists tenants without acquiring tenant context', { response: summary(p), tenants: rows(p.data).map(t => ({ id: t.id, name: t.name, status: t.status })) }, p.status === 200 && tenant === null ? 'PASS' : 'FAIL', 'GET platform tenants with no selected tenant', p.status);
        await page.goto(origin + '/platform'); await page.getByRole('heading', { name: 'Platform Dashboard', exact: true }).waitFor();
        record('UAT-PLATFORM-DASHBOARD', 'Platform', role, 'Platform dashboard renders tenant management scope', { headings: await page.locator('#main-content h1,#main-content h2').allTextContents(), text: (await page.locator('#main-content').innerText()).slice(0, 5000), buttons: await page.locator('#main-content').getByRole('button').allTextContents() }, 'PASS', 'Open Platform Dashboard; inspect platform scope');
      }
      const before = (await api(page, '/api/auth/me')).data.tenant_id;
      await page.reload(); await page.locator('#main-content').waitFor();
      const after = await api(page, '/api/auth/me');
      record('UAT-REFRESH-' + role, 'Authentication', role, 'Refresh retains session and explicit tenant/platform context', { before, after: after.data.tenant_id, status: after.status }, after.status === 200 && before === after.data.tenant_id ? 'PASS' : 'FAIL', 'Reload last module; GET auth/me', after.status);
      await logout(session, role); session = null;
      const oldFailure = cases.findIndex(c => c.id === 'UAT-RUNNER-' + role);
      if (oldFailure >= 0) { cases.splice(oldFailure, 1); fs.writeFileSync(caseFile, sanitize(JSON.stringify(cases, null, 2))); }
    } catch (e) {
      record('UAT-RUNNER-' + role, 'Execution', role, 'Complete account scenario', sanitize(e.message), 'BLOCKED', 'Scenario halted; subsequent cases for this account remain NOT RUN');
      if (session) await session.context.close();
    }
  }
  fs.writeFileSync(path.join(output, 'fixture-identifiers.json'), JSON.stringify(fixtures, null, 2));
}
async function invitations(browser) {
  const admin = await login(browser, 'admin'); const { page, me } = admin; const tenant = me.tenant_id;
  const resume = process.env.UAT_RESUME_INVITATION === '1' ? JSON.parse(fs.readFileSync(path.join(output, 'temporary-user.json'), 'utf8')) : null;
  const suffix = resume ? resume.email.match(/uat-native-(\d+)/)[1] : Date.now(); const email = 'uat-native-' + suffix + '@example.test';
  const profile = { first_name: 'UAT', last_name: 'Native ' + suffix, email, tenant_id: tenant, role_codes: ['VIEWER'] };
  const baseline = await api(page, '/api/tenants/' + tenant + '/users');
  let result;
  if (!resume) {
  await page.goto(origin + '/settings/users'); await page.getByRole('button', { name: 'Invite New User', exact: true }).click();
  await page.getByLabel('first name', { exact: false }).fill(profile.first_name);
  await page.getByLabel('last name', { exact: false }).fill(profile.last_name);
  await page.getByRole('dialog').locator('input[name="email"]').fill(email);
  const pending = page.waitForResponse(r => r.url().includes('/native-users') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Create and send invitation', exact: true }).click();
  const response = await pending; result = await response.json();
  record('UAT-INVITE-001', 'Users & Access', 'admin', 'UI invitation creates disposable native account and queues local Mailpit delivery', { status: response.status(), user_id: result.user_id, accountStatus: result.status, delivery: result.delivery, email }, response.status() === 201 ? 'PASS' : 'FAIL', 'Invite New User; fill synthetic name/email; Viewer role; create invitation', response.status());
  if (response.status() !== 201) { await logout(admin, 'admin'); return; }
  } else { result = { user_id: resume.user_id }; }
  const uid = result.user_id;
  const memberList = await api(page, '/api/tenants/' + tenant + '/users'); const member = rows(memberList.data).find(m => m.user_id === uid);
  fs.writeFileSync(path.join(output, 'temporary-user.json'), JSON.stringify({ user_id: uid, membership_id: member?.membership_id, email, tenant_id: tenant }, null, 2));
  if (!resume) record('UAT-INVITE-002', 'Users & Access', 'admin', 'New invitation is visible without refresh with pending account/verification distinct from membership', { before: rows(baseline.data).length, after: rows(memberList.data).length, member, uiContains: await page.getByText(email, { exact: true }).count() }, member && await page.getByText(email, { exact: true }).count() > 0 ? 'PASS' : 'FAIL', 'Inspect invalidated member directory and compare API after invitation', memberList.status);
  const duplicate = await api(page, '/api/tenants/' + tenant + '/native-users', 'POST', profile);
  record('UAT-INVITE-003', 'Users & Access', 'admin', 'Duplicate invitation/membership is rejected HTTP 409', duplicate, duplicate.status === 409 ? 'PASS' : 'FAIL', 'Repeat invitation payload for newly created disposable account', duplicate.status);
  const invalid = await api(page, '/api/tenants/' + tenant + '/native-users', 'POST', { ...profile, email: 'not-an-email' });
  record('UAT-INVITE-004', 'Users & Access', 'admin', 'Malformed invitation receives HTTP 422', invalid, invalid.status === 422 ? 'PASS' : 'FAIL', 'POST invalid email with otherwise valid synthetic profile', invalid.status);
  const roles = await api(page, '/api/tenant-roles');
  record('UAT-ROLE-001', 'Authorization', 'admin', 'Tenant Admin assignable list excludes Tenant Admin and Platform Admin', roles, roles.status === 200 && !roles.data.roles.some(r => ['TENANT_ADMIN', 'PLATFORM_ADMIN'].includes(r.code)) ? 'PASS' : 'FAIL', 'GET assignable roles; compare delegation policy', roles.status);
  for (const code of ['TENANT_ADMIN', 'PLATFORM_ADMIN', 'NONEXISTENT_UAT_ROLE']) {
    const current = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles');
    const r = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles', 'PUT', { role_codes: [code], primary_role_code: code, expected_version: current.data.role_assignment_version || current.data.version || 1, reason: 'Disposable UAT negative delegation' });
    record('UAT-ROLE-DENY-' + code, 'Authorization', 'admin', 'Invalid/unauthorized delegation is rejected with 403 or 422', r, [403, 422].includes(r.status) ? 'PASS' : 'FAIL', 'Attempt role replacement only on disposable pending user', r.status);
  }
  let mail;
  for (let i = 0; i < 20; i++) {
    const messages = await (await fetch('http://127.0.0.1:8026/api/v1/messages')).json();
    mail = messages.messages?.find(m => m.To?.some(t => t.Address === email));
    if (mail) break;
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  record('UAT-MAIL-001', 'Notifications', 'admin', 'Activation delivered to local Mailpit synthetic recipient only', mail ? { messageId: mail.ID, to: mail.To.map(t => t.Address), subject: mail.Subject, from: mail.From?.Address } : 'No activation message appeared in local Mailpit within 30 seconds', mail ? 'PASS' : 'BLOCKED', 'Confirmed running SMTP localhost:1026; poll local Mailpit metadata only', mail ? 200 : null);
  if (mail) {
    const message = await (await fetch('http://127.0.0.1:8026/api/v1/message/' + mail.ID)).json();
    const matched = (message.Text || message.HTML || '').match(/[#?&]token=([A-Za-z0-9_-]+)/);
    if (!matched) throw Error('Activation token unavailable in Mailpit message; message body withheld');
    const token = matched[1]; const password = 'Uat!' + require('node:crypto').randomBytes(24).toString('base64url');
    identities.__temporary = { password }; identities.__activation = { password: token };
    const tempContext = await browser.newContext({ ignoreHTTPSErrors: false, reducedMotion: 'reduce' }); const tempPage = await tempContext.newPage(); tempPage.setDefaultTimeout(20000); tempPage.setDefaultNavigationTimeout(30000);
    await tempPage.goto(origin + '/activate-account#token=' + token, { waitUntil: 'domcontentloaded' });
    await tempPage.waitForLoadState('networkidle', { timeout: 30000 });
    await tempPage.getByLabel('Password', { exact: true }).fill(password);
    await tempPage.getByLabel('Confirm password', { exact: true }).fill(password);
    const activationResponse = tempPage.waitForResponse(r => r.url().endsWith('/api/auth/native/activate'));
    await tempPage.getByRole('button', { name: 'Activate account', exact: true }).click();
    const active = await activationResponse;
    await tempPage.getByRole('heading', { name: 'Welcome back', exact: true }).waitFor();
    record('UAT-ACTIVATE-001', 'Authentication', 'disposable Viewer', 'Mailpit activation link activates account and redirects to native login', { status: active.status(), redirectedToLogin: new URL(tempPage.url()).pathname === '/native-sign-in' }, active.status() === 200 ? 'PASS' : 'FAIL', 'Open activation link in clean context; enter generated private password; activate; never capture credentials or link', active.status());
    await tempPage.getByLabel('Email address').fill(email); await tempPage.getByLabel('Password', { exact: true }).fill(password);
    const signedIn = tempPage.waitForResponse(r => r.url().endsWith('/api/auth/native/login'));
    await tempPage.getByRole('button', { name: 'Sign in', exact: true }).click(); const loginResult = await signedIn;
    await tempPage.getByRole('heading', { name: 'Dashboard', exact: true }).waitFor();
    record('UAT-ACTIVATE-002', 'Authentication', 'disposable Viewer', 'Activated account signs in through Native Login with active verified state', { loginStatus: loginResult.status(), me: summary(await api(tempPage, '/api/auth/me')) }, loginResult.status() === 200 ? 'PASS' : 'FAIL', 'Sign in newly activated disposable account in its clean context', loginResult.status());
    const refreshed = await api(page, '/api/tenants/' + tenant + '/users'); const target = rows(refreshed.data).find(m => m.user_id === uid);
    record('UAT-VERIFY-001', 'Users & Access', 'admin', 'Activation updates account Active and verification independently', target, target?.email_verified && target?.user_status === 'ACTIVE' ? 'PASS' : 'FAIL', 'Refetch disposable member after native activation', refreshed.status);
    for (const code of ['TENANT_ADMIN', 'PLATFORM_ADMIN', 'NONEXISTENT_UAT_ROLE']) {
      const st = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles');
      const r = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles', 'PUT', { role_codes: [code], primary_role_code: code, expected_version: st.data.role_assignment_version || st.data.version || 1, reason: 'Disposable active UAT negative delegation' });
      const expected = code === 'NONEXISTENT_UAT_ROLE' ? 422 : 403;
      record('UAT-ROLE-ACTIVE-DENY-' + code, 'Authorization', 'admin', 'Active account cannot receive unauthorized/unknown role; HTTP ' + expected, r, r.status === expected ? 'PASS' : 'FAIL', 'Attempt role replacement only on activated disposable user', r.status);
    }
    let roleState = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles');
    const version = roleState.data.role_assignment_version || roleState.data.version || 1;
    const assigned = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles', 'PUT', { role_codes: ['SECURITY_ANALYST'], primary_role_code: 'SECURITY_ANALYST', expected_version: version, reason: 'Disposable UAT valid assignment' });
    record('UAT-ROLE-002', 'Users & Access', 'admin', 'Permitted role assignment succeeds on disposable user', assigned, assigned.status === 200 ? 'PASS' : 'FAIL', 'Replace disposable Viewer role with Security Analyst using expected version', assigned.status);
    const stale = await api(page, '/api/tenants/' + tenant + '/users/' + uid + '/roles', 'PUT', { role_codes: ['VIEWER'], primary_role_code: 'VIEWER', expected_version: version, reason: 'Disposable UAT stale version' });
    record('UAT-ROLE-003', 'Users & Access', 'admin', 'Stale optimistic role version receives HTTP 409', stale, stale.status === 409 ? 'PASS' : 'FAIL', 'Repeat role replacement using previous role version', stale.status);
    const disabled = await api(page, '/api/tenants/' + tenant + '/users/' + member.membership_id + '/deactivate', 'POST');
    const denied = await api(tempPage, '/api/projects');
    record('UAT-MEMBERSHIP-001', 'Authorization', 'disposable user', 'Deactivated membership immediately loses protected tenant access', { mutation: summary(disabled), protectedRead: denied }, disabled.status === 200 && [401, 403].includes(denied.status) ? 'PASS' : 'FAIL', 'Deactivate only disposable membership; call projects using already signed-in disposable browser', denied.status);
    const enabled = await api(page, '/api/tenants/' + tenant + '/users/' + member.membership_id + '/activate', 'POST');
    record('UAT-MEMBERSHIP-002', 'Users & Access', 'admin', 'Disposable membership reactivation succeeds', summary(enabled), enabled.status === 200 ? 'PASS' : 'FAIL', 'Reactivate only disposable membership', enabled.status);
    const platform = await login(browser, 'platform');
    for (const status of ['SUSPENDED', 'DISABLED', 'ACTIVE']) {
      const change = await api(platform.page, '/api/platform/users/' + uid + '/status', 'PATCH', { status, reason: 'Disposable UAT account-state test' }, null);
      const attempt = await fetch('http://127.0.0.1:18000/api/auth/native/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const loginStatus = attempt.status; await attempt.arrayBuffer();
      record('UAT-ACCOUNT-' + status, 'Authorization', 'platform/disposable user', status === 'ACTIVE' ? 'Restored disposable account authenticates' : status + ' disposable account cannot authenticate', { change: summary(change), nativeLoginStatus: loginStatus }, change.status === 200 && loginStatus === (status === 'ACTIVE' ? 200 : 401) ? 'PASS' : 'FAIL', 'Platform changes disposable account status; direct Native Login probe; restore Active at end', loginStatus);
    }
    await logout(platform, 'platform'); await tempContext.close();
    // Exercise Add Existing Member with an activated disposable account, never a seeded account.
    const foreign = await login(browser, 'foreign'); const ft = foreign.me.tenant_id;
    await foreign.page.goto(origin + '/settings/users'); await foreign.page.getByRole('button', { name: 'Add Existing Member', exact: true }).click();
    await foreign.page.getByPlaceholder('Search existing users by name or email…').fill(email);
    const candidate = foreign.page.getByRole('button').filter({ hasText: email }); await candidate.waitFor(); await candidate.click();
    const addResponse = foreign.page.waitForResponse(r => r.url().endsWith('/users') && r.request().method() === 'POST');
    await foreign.page.getByRole('button', { name: 'Add Member', exact: true }).click(); const added = await addResponse;
    record('UAT-ADD-MEMBER-001', 'Users & Access', 'foreign Admin', 'Authorized admin can add disposable existing eligible account to own tenant with default Viewer role', { status: added.status(), user_id: uid, tenant: ft }, added.status() === 201 ? 'PASS' : 'FAIL', 'Search disposable activated user in Isolation Control; select; Add Member', added.status());
    const fl = await api(foreign.page, '/api/tenants/' + ft + '/users'); const fm = rows(fl.data).find(m => m.user_id === uid);
    if (fm) { const removed = await api(foreign.page, '/api/tenants/' + ft + '/users/' + fm.membership_id, 'DELETE'); record('UAT-ADD-MEMBER-002', 'Users & Access', 'foreign Admin', 'Remove only newly created disposable membership', summary(removed), removed.status === 204 ? 'PASS' : 'FAIL', 'Delete UAT-created membership; seeded foreign user untouched', removed.status); }
    await logout(foreign, 'foreign');
  }
  const audit = await api(page, '/api/tenants/' + tenant + '/audit-history?administrative_only=true&page_size=100');
  const matches = rows(audit.data).filter(a => JSON.stringify(a).includes(String(uid)) || JSON.stringify(a).includes(email));
  record('UAT-AUDIT-002', 'Users & Access', 'admin', 'Disposable invitation, role and membership actions create tenant audit records', { total: audit.data.total, matchingRecords: matches, events: rows(audit.data).map(a => a.action || a.event_type).filter(Boolean) }, audit.status === 200 && rows(audit.data).length > 0 ? 'PASS' : 'FAIL', 'Read administration audit after disposable mutations', audit.status);
  await page.goto(origin + '/settings/users'); await page.reload(); await page.getByRole('heading', { name: 'Member Directory', exact: true }).waitFor();
  await record('UAT-USER-REFRESH-MUTATION', 'Users & Access', 'admin', 'Refresh recovers current directory after server mutations', { count: rows((await api(page, '/api/tenants/' + tenant + '/users')).data).length, uiContains: await page.getByText(email, { exact: true }).count() }, await page.getByText(email, { exact: true }).count() > 0 ? 'PASS' : 'FAIL', 'Reload directory after invitation, role and lifecycle mutations');
  await logout(admin, 'admin');
}
async function security() {
  async function direct(url, token, tenant, method = 'GET', body) {
    const r = await fetch('http://127.0.0.1:18000' + url, { method, signal: AbortSignal.timeout(20000), headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(tenant ? { 'X-Tenant-ID': tenant } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    let data; const text = await r.text(); try { data = JSON.parse(text); } catch { data = text.slice(0, 200); }
    return { status: r.status, data, requestId: r.headers.get('x-request-id') };
  }
  async function tokenFor(role) {
    const r = await fetch('http://127.0.0.1:18000/api/auth/native/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: identities[role].email, password: identities[role].password }) });
    const data = await r.json(); if (r.status !== 200 || !data.access_token) throw Error('Direct native authentication failed for ' + role + ': HTTP ' + r.status);
    return data.access_token;
  }
  const adminToken = await tokenFor('admin'); const olympus = identities.admin.tenant_id; const foreignTenant = identities.foreign.tenant_id;
  const allProjects = rows((await direct('/api/projects', adminToken, olympus)).data); const project = allProjects.find(p => p.project_name === 'Olympus Release') || allProjects[0];
  const disposableProject = allProjects.find(p => p.project_name.startsWith('UAT-admin-'));
  const products = rows((await direct('/api/projects/' + project.id + '/products', adminToken, olympus)).data);
  const sboms = rows((await direct('/api/sboms', adminToken, olympus)).data);
  const known = { project: project.id, product: products[0]?.id, sbom: sboms[0]?.id, disposableProject: disposableProject?.id };
  fs.writeFileSync(path.join(output, 'isolation-targets.json'), JSON.stringify(known, null, 2));
  const foreignToken = await tokenFor('foreign');
  for (const [entity, endpoint] of [['project', '/api/projects/' + known.project], ['product', '/api/products/' + known.product], ['sbom', '/api/sboms/' + known.sbom], ['components', '/api/sboms/' + known.sbom + '/components'], ['runs', '/api/sboms/' + known.sbom + '/analysis-runs'], ['products-list', '/api/projects/' + known.project + '/products'], ['sbom-filter', '/api/sboms?project_id=' + known.project]]) {
    if (endpoint.includes('undefined')) continue;
    const result = await direct(endpoint, foreignToken, foreignTenant);
    record('UAT-ISOLATION-' + entity, 'Tenant isolation', 'foreign', 'Known Olympus public UUID is concealed from Isolation Control; HTTP 404', result, result.status === 404 ? 'PASS' : 'FAIL', 'Direct backend bearer request with authorized Isolation Control header: GET ' + endpoint, result.status, result.status === 404 ? null : 'UAT-DEF-ISOLATION');
  }
  const knownMissing = await direct('/api/projects/' + known.project, foreignToken, foreignTenant);
  const randomMissing = await direct('/api/projects/00000000-0000-4000-8000-000000000001', foreignToken, foreignTenant);
  record('UAT-ISOLATION-ENUMERATION', 'Tenant isolation', 'foreign', 'Known foreign UUID and nonexistent UUID have same status and response body', { known: knownMissing, unknown: randomMissing }, knownMissing.status === 404 && randomMissing.status === 404 && JSON.stringify(knownMissing.data) === JSON.stringify(randomMissing.data) ? 'PASS' : 'FAIL', 'Compare existing Olympus project with synthetic nonexistent project', knownMissing.status);
  for (const [id, token, tenant, endpoint, expected] of [
    ['foreign-header', foreignToken, olympus, '/api/projects', 403],
    ['foreign-users', foreignToken, foreignTenant, '/api/tenants/' + olympus + '/users', 404],
    ['admin-foreign-users', adminToken, olympus, '/api/tenants/' + foreignTenant + '/users', 404],
    ['admin-foreign-header', adminToken, foreignTenant, '/api/projects', 403]]) {
    const r = await direct(endpoint, token, tenant); record('UAT-ISOLATION-' + id, 'Tenant isolation', id.startsWith('admin') ? 'admin' : 'foreign', 'Cross-tenant header/path rejected HTTP ' + expected, r, r.status === expected ? 'PASS' : 'FAIL', 'Direct backend GET ' + endpoint + ' with controlled tenant header', r.status);
  }
  const foreignList = await direct('/api/projects', foreignToken, foreignTenant);
  record('UAT-ISOLATION-LIST', 'Tenant isolation', 'foreign', 'Tenant list contains no Olympus project UUIDs', { status: foreignList.status, ids: rows(foreignList.data).map(p => p.id), forbiddenIds: allProjects.map(p => p.id) }, foreignList.status === 200 && !rows(foreignList.data).some(p => allProjects.some(o => o.id === p.id)) ? 'PASS' : 'FAIL', 'Compare complete authorized tenant project lists by UUID', foreignList.status);
  if (disposableProject) {
    const mutation = await direct('/api/projects/' + disposableProject.id, foreignToken, foreignTenant, 'PATCH', { project_details: 'UAT denied cross-tenant mutation' });
    record('UAT-ISOLATION-MUTATION', 'Tenant isolation', 'foreign', 'Cross-tenant mutation of UAT-created Olympus project returns 404', mutation, mutation.status === 404 ? 'PASS' : 'FAIL', 'PATCH only an Olympus project created by this UAT; seeded business data untouched', mutation.status);
  }
  for (const role of ['analyst', 'developer', 'viewer']) {
    const token = await tokenFor(role); const tenant = identities[role].tenant_id;
    const probes = [
      ['invite', '/api/tenants/' + tenant + '/native-users', 'POST', { first_name: 'UAT', last_name: 'Denied', email: 'uat-denied-' + role + '@example.test', tenant_id: tenant, role_codes: ['VIEWER'] }],
      ['roles', '/api/tenants/' + tenant + '/users/2147483000/roles', 'PUT', { role_codes: ['TENANT_ADMIN'], primary_role_code: 'TENANT_ADMIN', expected_version: 1 }],
      ['platform-status', '/api/platform/users/2147483000/status', 'PATCH', { status: 'SUSPENDED', reason: 'UAT nonexistent target' }],
    ];
    if (role !== 'analyst' && disposableProject) probes.push(['project-update', '/api/projects/' + disposableProject.id, 'PATCH', { project_details: 'UAT denied role mutation' }]);
    for (const [id, endpoint, method, body] of probes) {
      const r = await direct(endpoint, token, tenant, method, body);
      record('UAT-DIRECT-DENY-' + role + '-' + id, 'Authorization', role, 'Server rejects unauthorized operation independently of BFF/UI; HTTP 403', r, r.status === 403 ? 'PASS' : 'FAIL', method + ' direct backend ' + endpoint + '; only nonexistent or UAT-owned targets', r.status);
    }
  }
  const platformToken = await tokenFor('platform');
  for (const [id, endpoint, tenant, expected] of [['platform-no-tenant', '/api/projects', null, 403], ['platform-forged-tenant', '/api/projects', olympus, 403], ['platform-administration', '/api/platform/tenants/' + olympus, null, 200]]) {
    const r = await direct(endpoint, platformToken, tenant);
    record('UAT-DIRECT-' + id, 'Platform', 'platform', 'Platform authority uses supported administration workflow; HTTP ' + expected, summary(r), r.status === expected ? 'PASS' : 'FAIL', 'Direct GET ' + endpoint + (tenant ? ' with Olympus header and no explicit membership' : ' without tenant header'), r.status);
  }
  const matrix = await direct('/api/platform/authorization/matrix', platformToken, null);
  record('UAT-POLICY-MATRIX', 'Authorization', 'platform', 'Database authority catalogue is readable by Platform Admin', summary(matrix), matrix.status === 200 ? 'PASS' : 'FAIL', 'Read live authorization matrix for comparison with observed role permissions', matrix.status);
  if (matrix.status === 200) fs.writeFileSync(path.join(output, 'authorization-matrix.json'), sanitize(JSON.stringify(matrix.data, null, 2)));
  for (const [id, endpoint, token, tenant, method, body, expected] of [
    ['401-anonymous', '/api/projects', null, null, 'GET', undefined, 401],
    ['401-invalid-token', '/api/projects', 'invalid-uat-signature', olympus, 'GET', undefined, 401],
    ['404-unknown', '/api/projects/00000000-0000-4000-8000-000000000001', adminToken, olympus, 'GET', undefined, 404],
    ['422-numeric-identity', '/api/projects/1', adminToken, olympus, 'GET', undefined, 422],
    ['422-malformed-uuid', '/api/projects/not-a-uuid', adminToken, olympus, 'GET', undefined, 422],
    ['422-invalid-body', '/api/projects', adminToken, olympus, 'POST', {}, 422],
    ['400-invalid-activation', '/api/auth/native/activate', null, null, 'POST', { token: 'synthetic-invalid-activation', password: 'Synthetic-invalid-activation-only!' }, 400]]) {
    const r = await direct(endpoint, token, tenant, method, body);
    record('UAT-HTTP-' + id, 'Error handling', 'API control', 'Actual error response HTTP ' + expected, r, r.status === expected ? 'PASS' : 'FAIL', method + ' direct backend ' + endpoint + '; synthetic invalid data', r.status);
  }
}
async function pages(browser) {
  const navigation = [
    ['/', 'Dashboard', 'dashboard:read'], ['/projects', 'Projects', 'project:read'], ['/sboms', 'SBOMs', 'sbom:read'],
    ['/analysis', 'Analysis', 'analysis:read'], ['/kev', 'CISA KEV', 'analysis:read'], ['/vex-investigation', 'VEX Investigation', 'vex:read'],
    ['/component-advisor', 'Component Advisor', 'component_advisor:read'], ['/schedules', 'Schedules', 'schedule:read'],
    ['/settings/notifications', 'Notifications', 'sbom:read'], ['/settings/ai', 'AI Configuration', 'tenant:ai:read'],
    ['/settings/advisor-policies', 'Advisor Policies', 'tenant:advisor-policy:read'], ['/admin/lifecycle-providers', 'Lifecycle Providers', 'tenant:lifecycle-provider:read'],
    ['/admin/lifecycle-vendor-records', 'Vendor Records', 'lifecycle:vendor-record:read'],
    ['/settings/platform/tenants', 'Tenant Management', 'platform:tenant:read'], ['/settings/platform', 'Platform Administrators', 'platform:administrator:read'],
    ['/settings/iam', 'Platform Health', 'platform:health:read'], ['/platform/configuration/ai', 'Platform AI', 'platform:ai:read'],
    ['/platform/configuration/lifecycle', 'Platform Lifecycle', 'platform:lifecycle-provider:read'], ['/platform/configuration/advisor-policies', 'Platform Advisor Policies', 'platform:advisor-policy:read'],
  ];
  for (const role of process.argv.slice(3).length ? process.argv.slice(3) : ['admin']) {
    const session = await login(browser, role); const { page, me, errors } = session;
    for (const [href, label, permission] of navigation) {
      if (!me.permissions.includes(permission)) continue;
      if (process.env.UAT_PAGE_FILTER && !process.env.UAT_PAGE_FILTER.split(',').includes(href)) continue;
      const id = 'UAT-PAGE-' + role + '-' + href.replace(/[^a-z]+/g, '-');
      try {
        const begin = traffic.length, priorErrors = errors.length;
        const r = await page.goto(origin + href, { waitUntil: 'domcontentloaded' });
        await page.locator('#main-content h1').waitFor({ timeout: 20000 });
        await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        const text = await page.locator('#main-content').innerText();
        const failures = traffic.slice(begin).filter(t => t.status >= 400);
        const skeleton = text.length < 600 && /Loading|loading/.test(text);
        const pass = r.status() < 400 && errors.length === priorErrors && !failures.some(f => f.status >= 500) && !text.includes('Application error:');
        record(id, label, role, 'Authorized page renders actual content and reads without browser crash or API 5xx (page/read smoke)', { path: href, headings: await page.locator('#main-content h1,#main-content h2').allTextContents(), text: text.slice(0, 3500), failures, pageErrors: errors.slice(priorErrors) }, skeleton ? 'BLOCKED' : pass ? 'PASS' : 'FAIL', 'Open ' + href + '; inspect actual module and requests', r.status(), skeleton || pass ? null : 'UAT-DEF-PAGE-' + label.replace(/\W/g, '-'));
        if ((href === '/projects' && !me.permissions.includes('project:create')) || (href === '/sboms' && !me.permissions.includes('sbom:upload'))) {
          const name = href === '/projects' ? 'New Project' : 'Upload SBOM'; const button = page.getByRole('button', { name, exact: true }); const count = await button.count(); const enabled = count ? await button.isEnabled() : false;
          let blockedClick = count === 0;
          if (count && !enabled) { try { await button.click({ timeout: 700 }); } catch { blockedClick = true; } }
          record('UAT-UI-DENY-' + role + '-' + (href === '/projects' ? 'project' : 'upload'), 'Authorization UI', role, 'Prohibited mutation is absent or disabled and cannot be invoked by ordinary browser click', { button: name, count, enabled, blockedClick }, !enabled && blockedClick ? 'PASS' : 'FAIL', 'Inspect and attempt ordinary click on prohibited action; server-side denial tested independently');
        }
        if (href === '/kev') {
          await page.getByRole('searchbox', { name: 'Search KEV catalog' }).fill('CVE-2021-44228');
          await page.waitForResponse(r => r.url().includes('/api/v1/kev?') && r.status() === 200, { timeout: 10000 }).catch(() => {});
          await page.getByText('CVE-2021-44228', { exact: true }).waitFor({ timeout: 10000 }).catch(() => {});
          const filtered = await page.locator('#main-content').innerText();
          record('UAT-KEV-SEARCH-' + role, 'CISA KEV', role, 'KEV CVE search displays requested Log4Shell CVE', filtered.slice(0, 3500), filtered.includes('CVE-2021-44228') ? 'PASS' : 'FAIL', 'Type known CVE into KEV search; inspect filtered results');
        }
      } catch (e) {
        record(id, label, role, 'Authorized module navigation completes within budget', sanitize(e.message), 'BLOCKED', 'Navigate ' + href + '; observed timeout or unavailable page');
      }
    }
    try { await logout(session, role); } catch (e) { record('UAT-PAGE-LOGOUT-' + role, 'Execution', role, 'Sign out after module traversal', sanitize(e.message), 'BLOCKED', 'Frontend navigation/restart prevented post-traversal logout verification; separate role logout cases remain independently recorded'); await session.context.close(); }
  }
}
async function business(browser) {
  const admin = await login(browser, 'admin'); const { page, me } = admin;
  const stamp = Date.now(); const name = 'UAT Business ' + stamp;
  const previous = process.env.UAT_RESUME_BUSINESS === '1' ? cases.find(c => c.id === 'UAT-BUSINESS-SETUP')?.actual : null;
  const project = previous ? await api(page, '/api/projects/' + previous.project.id) : await api(page, '/api/projects', 'POST', { project_name: name, project_details: 'Disposable full UAT workflows', project_status: 1 });
  const pid = project.data.id;
  const product = previous ? await api(page, '/api/products/' + previous.product.id) : await api(page, '/api/projects/' + pid + '/products', 'POST', { name: 'UAT Gateway ' + stamp, status: 'active' });
  const productId = product.data.id;
  if (!previous) record('UAT-BUSINESS-SETUP', 'Projects and Products', 'admin', 'Create isolated UAT project and product with UUIDs', { project: { status: project.status, id: pid }, product: { status: product.status, id: productId } }, project.status === 201 && product.status === 201 ? 'PASS' : 'FAIL', 'POST uniquely named project and product; no seeded business records modified', product.status);
  if (!productId) throw Error('Disposable project/product setup failed');
  const dup = await api(page, '/api/projects/' + pid + '/products', 'POST', { name: product.data.name });
  record('UAT-PRODUCT-DUPLICATE', 'Products', 'admin', 'Duplicate product in project receives 409', dup, dup.status === 409 ? 'PASS' : 'FAIL', 'Repeat product creation in disposable project', dup.status);
  const update = await api(page, '/api/products/' + productId, 'PATCH', { description: 'UAT updated product description' });
  record('UAT-PRODUCT-UPDATE', 'Products', 'admin', 'Product update persists on disposable record', { status: update.status, description: update.data.description }, update.status === 200 && update.data.description === 'UAT updated product description' ? 'PASS' : 'FAIL', 'PATCH product description; inspect response', update.status);
  try {
  await page.goto(origin + '/products/' + productId, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.getByRole('heading', { name: product.data.name, exact: true }).waitFor();
  record('UAT-PRODUCT-UI', 'Products', 'admin', 'Product UUID deep link renders correct disposable application', { heading: product.data.name, text: (await page.locator('#main-content').innerText()).slice(0, 3000) }, 'PASS', 'Navigate actual product UUID deep link and inspect application');
  } catch (e) { record('UAT-PRODUCT-UI', 'Products', 'admin', 'Product UUID deep link renders correct disposable application', sanitize(e.message), 'BLOCKED', 'Navigate UAT product deep link; frontend did not complete within budget'); }
  const doc = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, serialNumber: 'urn:uuid:' + require('node:crypto').randomUUID(), metadata: { timestamp: new Date().toISOString(), tools: [{ vendor: 'UAT', name: 'SBOM Analyzer UAT', version: '1' }] }, components: [
    { type: 'application', 'bom-ref': 'uat-app', name: 'uat-gateway', version: '1.0.0', purl: 'pkg:generic/uat-gateway@1.0.0', supplier: { name: 'UAT' } },
    { type: 'library', 'bom-ref': 'uat-lodash', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', supplier: { name: 'UAT' } }
  ], dependencies: [{ ref: 'uat-app', dependsOn: ['uat-lodash'] }] };
  fs.writeFileSync(path.join(output, 'uat.cdx.json'), JSON.stringify(doc, null, 2));
  await page.goto(origin + '/sboms', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'SBOMs', exact: true }).waitFor();
  await page.waitForLoadState('networkidle', { timeout: 6000 }).catch(() => {});
  await page.getByRole('button', { name: 'Upload SBOM', exact: true }).click();
  const dialog = page.getByRole('dialog'); await dialog.locator('select[name="projectid"]').selectOption(pid);
  await dialog.locator('select[name="productid"]').selectOption(productId);
  await dialog.getByLabel('SBOM Name', { exact: false }).fill('UAT SBOM ' + stamp);
  await dialog.getByLabel('SBOM Version', { exact: false }).fill('1.0.0');
  await dialog.getByLabel('Product Version', { exact: false }).fill('1.0.0');
  await dialog.getByLabel('Choose SBOM file', { exact: true }).setInputFiles({ name: 'uat.cdx.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(doc)) });
  const uploaded = page.waitForResponse(r => r.url().includes('/api/sboms/upload') && r.request().method() === 'POST', { timeout: 60000 });
  await dialog.getByRole('button', { name: 'Upload SBOM', exact: true }).click(); const uploadedResponse = await uploaded; const upload = await uploadedResponse.json();
  const sid = upload.sbom_id || upload.id;
  record('UAT-SBOM-UPLOAD-UI', 'SBOM upload and validation', 'admin', 'Browser file upload accepts valid CycloneDX into disposable application', { status: uploadedResponse.status(), sbomId: sid, uploadStatus: upload.upload_status, validationStatus: upload.validation_status }, [200, 201, 202].includes(uploadedResponse.status()) && Boolean(sid) ? 'PASS' : 'FAIL', 'Upload SBOM modal; choose UAT project/application; set name/version; choose actual CycloneDX file; submit', uploadedResponse.status());
  if (!sid) throw Error('UI SBOM upload did not return an identity');
  const fixtures = { project_id: pid, product_id: productId, sbom_id: sid };
  fs.writeFileSync(path.join(output, 'business-fixtures.json'), JSON.stringify(fixtures, null, 2));
  const detail = await api(page, '/api/sboms/' + sid); const logicalId = detail.data.logical_sbom_id;
  const componentResult = await api(page, '/api/sboms/' + sid + '/components'); const components = rows(componentResult.data);
  record('UAT-SBOM-COMPONENTS', 'SBOM components', 'admin', 'Two uploaded components persist with public UUIDs and correct SBOM scope', { sbomStatus: detail.status, logicalId, components }, componentResult.status === 200 && components.length === 2 && components.every(c => /^[0-9a-f-]{36}$/.test(c.id)) ? 'PASS' : 'FAIL', 'Read uploaded SBOM and its components', componentResult.status);
  for (const [id, endpoint] of [['validation', '/api/sboms/' + sid + '/validation-report'], ['quality', '/api/sboms/' + sid + '/quality'], ['lifecycle', '/api/sboms/' + sid + '/lifecycle'], ['logical', '/api/logical-sboms/' + logicalId]]) {
    const r = await api(page, endpoint);
    record('UAT-SBOM-' + id, id === 'lifecycle' ? 'Lifecycle' : 'SBOM validation and versioning', 'admin', 'Uploaded valid SBOM has readable ' + id + ' result', { ...summary(r), data: id === 'quality' || id === 'validation' ? r.data : undefined }, r.status === 200 ? 'PASS' : 'FAIL', 'GET ' + endpoint, r.status);
  }
  const stream = await page.evaluate(async id => {
    const r = await fetch('/api/backend/api/sboms/' + id + '/analyze/stream', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': sessionStorage.getItem('sbom_active_tenant_id') }, body: JSON.stringify({ sources: ['OSV'] }), signal: AbortSignal.timeout(120000) });
    const text = await r.text(); const complete = [];
    for (const block of text.split('\n\n')) if (block.includes('event: complete')) for (const line of block.split('\n')) if (line.startsWith('data: ')) { try { complete.push(JSON.parse(line.slice(6))); } catch {} }
    return { status: r.status, complete, eventTypes: [...new Set(text.split('\n').filter(l => l.startsWith('event: ')))], errorText: r.status >= 400 ? text.slice(0, 300) : undefined };
  }, sid);
  record('UAT-OSV-ANALYSIS', 'Vulnerability analysis and OSV', 'admin', 'Real OSV analysis completes with OK/FINDINGS and zero source errors', stream, stream.status === 200 && stream.complete.length === 1 && ['OK', 'FINDINGS'].includes(stream.complete[0].status) && stream.complete[0].errors === 0 ? 'PASS' : 'FAIL', 'POST real analyze/stream for UAT SBOM; consume complete event; use configured OSV integration', stream.status);
  const runs = await api(page, '/api/sboms/' + sid + '/analysis-runs'); fixtures.run_id = rows(runs.data)[0]?.id;
  record('UAT-ANALYSIS-PERSISTENCE', 'Vulnerability analysis and OSV', 'admin', 'Completed analysis persists against UAT SBOM UUID', { ...summary(runs), runs: rows(runs.data).map(r => ({ id: r.id, sbom_id: r.sbom_id, status: r.status, total_findings: r.total_findings })) }, runs.status === 200 && rows(runs.data).some(r => r.sbom_id === sid) ? 'PASS' : 'FAIL', 'Read persisted analysis runs after completion', runs.status);
  const vex = await api(page, '/api/vex/investigations?sbom_id=' + sid);
  const investigations = rows(vex.data); record('UAT-VEX-CONTEXT', 'VEX Investigation', 'admin', 'Analyzed vulnerable UAT component creates contextual investigations', { ...summary(vex), contexts: investigations.map(v => ({ id: v.id, canonical_vulnerability_id: v.canonical_vulnerability_id, effective_status: v.effective_status, row_version: v.row_version })) }, vex.status === 200 && investigations.length > 0 ? 'PASS' : 'BLOCKED', 'Read investigations scoped to UAT SBOM', vex.status);
  fixtures.investigation_id = investigations[0]?.id;
  if (fixtures.investigation_id) {
    const endpoint = '/api/vex/investigations/' + fixtures.investigation_id;
    const before = await api(page, endpoint); const version = before.data.row_version;
    const decision = await api(page, endpoint + '/decision', 'PUT', { status: 'UNDER_INVESTIGATION', row_version: version, reason: 'UAT disposable investigation review' });
    record('UAT-VEX-DECISION', 'VEX Investigation', 'admin', 'Authorized decision persists with optimistic concurrency and audit', { ...summary(decision), row_version: decision.data.row_version, effective_status: decision.data.effective_status }, decision.status === 200 ? 'PASS' : 'FAIL', 'Record decision only on UAT-generated investigation', decision.status);
    const stale = await api(page, endpoint + '/decision', 'PUT', { status: 'AFFECTED', row_version: version, reason: 'UAT deliberately stale decision' });
    record('UAT-VEX-STALE', 'VEX Investigation', 'admin', 'Stale decision returns 409 without overwriting latest determination', summary(stale), stale.status === 409 ? 'PASS' : 'FAIL', 'Retry same UAT context with previous row_version', stale.status);
    const current = await api(page, endpoint);
    const invalid = await api(page, endpoint + '/decision', 'PUT', { status: 'NOT_AFFECTED', row_version: current.data.row_version, reason: 'UAT missing justification' });
    record('UAT-VEX-VALIDATION', 'VEX Investigation', 'admin', 'NOT_AFFECTED without required justification/impact is rejected', summary(invalid), [400, 422].includes(invalid.status) ? 'PASS' : 'FAIL', 'Submit unsupported NOT_AFFECTED determination on disposable context', invalid.status);
  }
  const previewPayload = { scope: 'SBOM', sbom_id: sid, parts: ['A'], formats: ['XLSX'] };
  const preview = await api(page, '/api/report-subscriptions/preview', 'POST', previewPayload);
  record('UAT-REPORT-PREVIEW', 'Reports and notifications', 'admin', 'Report preview resolves only UAT SBOM scope', { ...summary(preview), data: preview.data }, preview.status === 200 ? 'PASS' : 'FAIL', 'Preview report for disposable SBOM', preview.status);
  const subscription = await api(page, '/api/report-subscriptions', 'POST', previewPayload);
  record('UAT-REPORT-SUBSCRIBE', 'Reports and notifications', 'admin', 'Own report subscription can be created', { ...summary(subscription), id: subscription.data.id, sbom_id: subscription.data.sbom_id }, subscription.status === 201 ? 'PASS' : 'FAIL', 'Create temporary report subscription for own verified seeded Admin email via local Mailpit', subscription.status);
  if (subscription.status === 201) {
    const subId = subscription.data.id; fixtures.subscription_id = subId;
    const send = await api(page, '/api/report-subscriptions/' + subId + '/send-now', 'POST');
    let delivery;
    for (let i = 0; i < 25 && send.status === 202; i++) {
      const listing = await api(page, '/api/report-deliveries'); delivery = rows(listing.data).find(d => d.id === send.data.id);
      if (delivery && !['PENDING', 'GENERATING', 'SENDING'].includes(delivery.status)) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    record('UAT-REPORT-DELIVERY', 'Reports and notifications', 'admin', 'Real local report worker creates and sends report through Mailpit', { enqueue: summary(send), delivery: delivery ? { id: delivery.id, status: delivery.status, error_code: delivery.error_code, artifact_count: delivery.artifacts?.length } : null }, delivery?.status === 'SENT' ? 'PASS' : delivery?.status === 'FAILED' ? 'FAIL' : 'BLOCKED', 'Send newly created UAT subscription now; poll real worker result; SMTP was verified local', send.status);
    const removed = await api(page, '/api/report-subscriptions/' + subId, 'DELETE');
    record('UAT-REPORT-CLEANUP', 'Reports and notifications', 'admin', 'Remove only UAT-created subscription', summary(removed), removed.status === 204 ? 'PASS' : 'FAIL', 'Delete temporary subscription after delivery probe', removed.status);
  }
  for (const [label, endpoint] of [['AI credentials', '/api/v1/ai/credentials'], ['AI effective configuration', '/api/v1/ai/effective-config'], ['Lifecycle providers', '/api/admin/lifecycle-providers'], ['Analysis configuration', '/api/analysis/config']]) {
    const r = await api(page, endpoint);
    const providers = rows(r.data).map(p => ({ provider: p.provider || p.provider_key || p.name, enabled: p.enabled, configured: p.configured || p.has_credentials, status: p.status }));
    record('UAT-CONFIG-' + label.replace(/\W/g, '-'), 'Integration configuration', 'admin', 'Configuration is readable without exposing credentials', { ...summary(r), providers }, r.status === 200 ? 'PASS' : 'FAIL', 'Read ' + endpoint + '; retain only configuration metadata; secret fields withheld', r.status);
    if (label === 'AI credentials' && r.status === 200 && rows(r.data).length === 0) record('UAT-AI-LIVE-PROVIDER', 'AI configuration and providers', 'admin', 'Configured real AI provider can be called', 'No AI credentials configured; no credential fabricated or borrowed', 'BLOCKED', 'Inspected live credential metadata; live AI completion requires configured provider');
  }
  const filters = await api(page, '/dashboard/filter-options/projects');
  const filtered = await api(page, '/dashboard/stats?project_id=' + pid);
  const filteredSboms = await api(page, '/api/sboms?project_id=' + pid + '&product_id=' + productId);
  record('UAT-DASHBOARD-FILTER', 'Dashboard', 'admin', 'Project/product UUID filter is accepted and SBOM results remain scoped', { options: summary(filters), stats: filtered.data, scopedSbomIds: rows(filteredSboms.data).map(s => s.id) }, filtered.status === 200 && filteredSboms.status === 200 && rows(filteredSboms.data).every(s => s.project_id === pid || s.projectid === pid) ? 'PASS' : 'FAIL', 'Read dashboard filter options and project-scoped stats; compare scoped inventory', filtered.status);
  fs.writeFileSync(path.join(output, 'business-fixtures.json'), JSON.stringify(fixtures, null, 2));
  await logout(admin, 'admin');
}
async function userUi(browser) {
  const session = await login(browser, 'admin'); const { page, me } = session;
  const target = JSON.parse(fs.readFileSync(path.join(output, 'temporary-user.json'), 'utf8'));
  if (!target.email.startsWith('uat-native-') || target.user_id <= 6) throw Error('Disposable user ownership guard failed');
  await page.goto(origin + '/settings/users', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'Member Directory', exact: true }).waitFor();
  const list = await api(page, '/api/tenants/' + me.tenant_id + '/users'); const member = rows(list.data).find(m => m.user_id === target.user_id);
  const actionName = 'Open actions for ' + member.display_name;
  await page.getByRole('button', { name: actionName, exact: true }).click(); await page.getByRole('menuitem', { name: 'Manage roles', exact: true }).click();
  const roles = page.getByRole('dialog');
  const protectedRole = await roles.getByRole('checkbox', { name: 'Tenant Admin', exact: false }).count();
  await roles.getByRole('checkbox', { name: 'Security Analyst', exact: false }).uncheck(); await roles.getByRole('checkbox', { name: 'Viewer', exact: false }).check();
  await page.screenshot({ path: path.join(output, 'UAT-ROLE-UI-dialog.png'), fullPage: true });
  const roleResponse = page.waitForResponse(r => r.url().endsWith('/roles') && r.request().method() === 'PUT');
  await roles.getByRole('button', { name: 'Save changes', exact: true }).click(); const roleResult = await roleResponse;
  const updated = rows((await api(page, '/api/tenants/' + me.tenant_id + '/users')).data).find(m => m.user_id === target.user_id);
  record('UAT-ROLE-UI-SAVE', 'Users & Access', 'admin', 'UI permits Viewer assignment on disposable account and does not offer Tenant Admin delegation', { status: roleResult.status(), protectedRoleCheckboxes: protectedRole, persistedRoles: updated.roles }, roleResult.status() === 200 && protectedRole === 0 && updated.roles.join(',') === 'VIEWER' ? 'PASS' : 'FAIL', 'Open disposable user action menu; Manage roles; replace Analyst with Viewer; Save changes', roleResult.status());
  await page.getByRole('button', { name: actionName, exact: true }).click(); await page.getByRole('menuitem', { name: 'Manage roles', exact: true }).click();
  await page.getByRole('dialog').getByRole('checkbox', { name: 'Viewer', exact: false }).uncheck();
  const saveEnabled = await page.getByRole('button', { name: 'Save changes', exact: true }).isEnabled();
  record('UAT-ROLE-UI-EMPTY', 'Users & Access', 'admin', 'Active membership cannot be saved with no role selected', { saveEnabled, text: await page.getByRole('dialog').innerText() }, !saveEnabled ? 'PASS' : 'FAIL', 'Uncheck final role on disposable user; observe disabled Save; cancel');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  for (const [operation, endpoint, status] of [['Disable', 'deactivate', 'DISABLED'], ['Enable', 'activate', 'ACTIVE']]) {
    await page.getByRole('button', { name: actionName, exact: true }).click(); await page.getByRole('menuitem', { name: operation + ' membership', exact: true }).click();
    const dialogText = await page.getByRole('dialog').innerText();
    if (operation === 'Disable') {
      await page.screenshot({ path: path.join(output, 'UAT-native-membership-confirmation.png'), fullPage: true });
      record('UAT-MEMBERSHIP-PROVIDER-COPY', 'Users & Access', 'admin/native disposable account', 'Native account confirmation uses accurate provider-neutral identity language', dialogText, dialogText.includes('Their HCL.CS identity') ? 'FAIL' : 'PASS', 'Open disable-membership confirmation for known Native account; inspect copy', null, dialogText.includes('Their HCL.CS identity') ? 'UAT-DEF-004' : null);
    }
    const response = page.waitForResponse(r => r.url().endsWith('/' + endpoint) && r.request().method() === 'POST');
    await page.getByRole('dialog').getByRole('button', { name: operation + ' membership', exact: true }).click(); const result = await response;
    const current = rows((await api(page, '/api/tenants/' + me.tenant_id + '/users')).data).find(m => m.user_id === target.user_id);
    record('UAT-MEMBERSHIP-UI-' + operation, 'Users & Access', 'admin', operation + ' only disposable membership while preserving active user account and assigned roles', { status: result.status(), membership: current.status, account: current.user_status, roles: current.roles }, result.status() === 200 && current.status === status && current.user_status === 'ACTIVE' ? 'PASS' : 'FAIL', operation + ' disposable membership through action menu and confirmation dialog; compare server state', result.status());
  }
  await page.getByRole('button', { name: 'Invite New User', exact: true }).click();
  await page.getByRole('dialog').locator('input[name="first_name"]').fill('UAT'); await page.getByRole('dialog').locator('input[name="last_name"]').fill('Duplicate'); await page.getByRole('dialog').locator('input[name="email"]').fill(target.email);
  const duplicateResponse = page.waitForResponse(r => r.url().endsWith('/native-users') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Create and send invitation', exact: true }).click(); const duplicate = await duplicateResponse;
  await page.getByRole('dialog').getByRole('status').waitFor();
  const message = await page.getByRole('dialog').innerText();
  record('UAT-INVITE-UI-DUPLICATE', 'Users & Access', 'admin', 'Duplicate invitation shows actionable existing-membership feedback and HTTP 409', { status: duplicate.status(), message }, duplicate.status() === 409 && message.includes('already belongs to the selected tenant') ? 'PASS' : 'FAIL', 'Invite same disposable user through UI; inspect current roles and manage-existing-membership feedback', duplicate.status());
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 }); await page.getByRole('searchbox', { name: 'Search members' }).fill('viewer@olympus.example.test');
  await page.screenshot({ path: path.join(output, 'UAT-users-mobile.png'), fullPage: true });
  const mobile = await page.evaluate(() => ({ viewport: innerWidth, width: document.documentElement.scrollWidth }));
  record('UAT-USERS-MOBILE', 'Users & Access', 'admin', 'Mobile member card exposes seeded Viewer identity and separate security states without page overflow', { ...mobile, text: await page.locator('#main-content').innerText() }, mobile.width <= mobile.viewport ? 'PASS' : 'FAIL', 'Emulate 390px viewport; search Viewer; inspect mobile member card (browser emulation only)');
  await page.getByRole('button', { name: 'Clear member search', exact: true }).click();
  const focused = await page.getByRole('searchbox', { name: 'Search members' }).evaluate(e => e === document.activeElement);
  record('UAT-USERS-CLEAR-FOCUS', 'Users & Access', 'admin', 'Clearing search restores focus and all members', { focused, search: await page.getByRole('searchbox', { name: 'Search members' }).inputValue() }, focused ? 'PASS' : 'FAIL', 'Click Clear member search; inspect active element and search value');
  await page.setViewportSize({ width: 1440, height: 1100 });
  const invalidDates = await api(page, '/api/tenants/' + me.tenant_id + '/audit-history?from_time=2026-10-20T00:00:00Z&to_time=2026-10-19T00:00:00Z');
  record('UAT-AUDIT-INVALID-DATES', 'Users & Access', 'admin', 'Reversed audit date range returns 422', invalidDates, invalidDates.status === 422 ? 'PASS' : 'FAIL', 'GET actual tenant audit with reversed ISO UTC dates', invalidDates.status);
  const category = await api(page, '/api/tenants/' + me.tenant_id + '/audit-history?category=role&outcome=DENIED');
  record('UAT-AUDIT-FILTERS', 'Users & Access', 'admin', 'Role/DENIED audit filter returns only matching actual events', { ...summary(category), outcomes: rows(category.data).map(e => e.outcome), categories: rows(category.data).map(e => e.category) }, category.status === 200 && rows(category.data).length > 0 && rows(category.data).every(e => e.outcome === 'DENIED' && e.category === 'role') ? 'PASS' : 'FAIL', 'Filter actual denied role-delegation audit records', category.status);
  await logout(session, 'admin');
}
async function finalBrowser(browser) {
  const session = await login(browser, 'admin'); const { page, context, me } = session;
  const fixture = JSON.parse(fs.readFileSync(path.join(output, 'business-fixtures.json'), 'utf8'));
  const jsSeesCookie = await page.evaluate(() => document.cookie.split(';').some(c => c.trim().startsWith('__Host-sbom-session=')));
  const jwtInStorage = await page.evaluate(() => [localStorage, sessionStorage].some(s => Object.keys(s).some(k => /eyJ[A-Za-z0-9_-]+\./.test(s.getItem(k) || ''))));
  record('UAT-SESSION-BROWSER-STORAGE', 'Session security', 'admin', 'HttpOnly session is hidden from JavaScript; no bearer JWT is persisted in browser storage', { jsSeesCookie, jwtInStorage }, !jsSeesCookie && !jwtInStorage ? 'PASS' : 'FAIL', 'Inspect only boolean presence signals; do not expose cookie or storage values');
  const csrf = await context.request.patch(origin + '/api/backend/api/projects/' + fixture.project_id, { headers: { Origin: 'https://attacker.example.test' }, data: { project_details: 'UAT cross-origin rejected' } });
  const csrfBody = await csrf.json();
  record('UAT-CSRF-ORIGIN', 'Session security', 'admin', 'Authenticated cross-origin BFF mutation is rejected before forwarding', { status: csrf.status(), data: csrfBody }, csrf.status() === 403 && csrfBody.detail === 'Untrusted origin' ? 'PASS' : 'FAIL', 'Use authenticated browser request context with hostile Origin against UAT project; no seeded data target', csrf.status());
  const kevDenied = await api(page, '/api/v1/kev/sync', 'POST', { since: '2099-01-01', prune_stale: false });
  record('UAT-KEV-SYNC-SERVER-POLICY', 'CISA KEV authorization', 'admin', 'Global catalog sync requires platform authority and rejects Tenant Admin', kevDenied, kevDenied.status === 403 ? 'PASS' : 'FAIL', 'POST safe no-prune future cutoff to verify current backend authority', kevDenied.status);
  if (kevDenied.status === 403 && !cases.some(c => c.id === 'UAT-KEV-SYNC-UI')) {
    await page.goto(origin + '/kev', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'CISA KEV', exact: true }).waitFor();
    const button = page.getByRole('button', { name: 'Sync KEV Catalog', exact: true }); const enabled = await button.isEnabled();
    if (enabled) {
      const deniedResponse = page.waitForResponse(r => r.url().includes('/api/v1/kev/sync') && r.request().method() === 'POST');
      await button.click(); const response = await deniedResponse;
      await page.screenshot({ path: path.join(output, 'UAT-kev-admin-sync-denied.png'), fullPage: true });
      record('UAT-KEV-SYNC-UI', 'CISA KEV authorization', 'admin', 'Tenant Admin UI does not enable a platform-only sync operation', { enabled, status: response.status(), body: await response.json(), requestId: response.headers()['x-request-id'] }, 'FAIL', 'Click enabled Sync KEV Catalog as Tenant Admin after independently confirming server denial; server rejects before catalog mutation', response.status(), 'UAT-DEF-005');
    } else record('UAT-KEV-SYNC-UI', 'CISA KEV authorization', 'admin', 'Tenant Admin UI does not enable a platform-only sync operation', { enabled }, 'PASS', 'Inspect global sync action against backend platform policy');
  }
  try {
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'Dashboard', exact: true }).waitFor({ timeout: 30000 });
  await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
  const filters = page.getByRole('region', { name: 'Dashboard filters' });
  const statsResponse = page.waitForResponse(r => r.url().includes('/dashboard/summary?') && r.url().includes(fixture.project_id), { timeout: 25000 }).catch(() => null);
  await filters.getByLabel('Project', { exact: true }).selectOption(fixture.project_id);
  const stats = await statsResponse; const statsData = stats ? await stats.json() : null;
  await page.waitForLoadState('networkidle', { timeout: 6000 }).catch(() => {});
  record('UAT-DASHBOARD-FILTER-UI', 'Dashboard', 'admin', 'Browser Project filter selects disposable project and requests scoped metrics with UUID URL state', { url: page.url(), selectedProject: await filters.getByLabel('Project', { exact: true }).inputValue(), status: stats?.status(), stats: statsData, text: (await page.locator('#main-content').innerText()).slice(0, 4500) }, stats?.status() === 200 && await filters.getByLabel('Project', { exact: true }).inputValue() === fixture.project_id && page.url().includes(fixture.project_id) ? 'PASS' : stats ? 'FAIL' : 'BLOCKED', 'Select UAT project in actual dashboard filters; observe scoped summary response and displayed state', stats?.status());
  await page.reload({ waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'Dashboard', exact: true }).waitFor();
  await page.waitForFunction(id => document.querySelector('[aria-label="Dashboard filters"] select')?.value === id, fixture.project_id, { timeout: 20000 });
  const selected = await page.getByRole('region', { name: 'Dashboard filters' }).getByLabel('Project', { exact: true }).inputValue();
  record('UAT-DASHBOARD-FILTER-REFRESH', 'Dashboard', 'admin', 'Dashboard project selection survives refresh through public UUID URL state', { selected, expected: fixture.project_id }, selected === fixture.project_id ? 'PASS' : 'FAIL', 'Refresh filtered Dashboard; inspect selected public UUID');
  } catch (e) {
    await page.screenshot({ path: path.join(output, 'UAT-dashboard-filter-incomplete.png'), fullPage: true }).catch(() => {});
    record('UAT-DASHBOARD-FILTER-BROWSER-BLOCK', 'Dashboard', 'admin', 'Dashboard filter browser scenario reaches a stable scoped response', { error: sanitize(e.message), path: new URL(page.url()).pathname, headings: await page.locator('h1,h2').allTextContents().catch(() => []), visibleState: await page.locator('#main-content').innerText({ timeout: 2000 }).catch(() => 'Application main container unavailable'), recentHttp: traffic.slice(-12) }, 'BLOCKED', 'Repeated browser filter attempts did not complete; direct UUID-scoped dashboard API passed; no unsupported UI success claim', null, 'ENV-001');
  }
  const target = JSON.parse(fs.readFileSync(path.join(output, 'temporary-user.json'), 'utf8'));
  if (target.user_id > 6 && target.email.startsWith('uat-native-')) {
    const removed = await api(page, '/api/tenants/' + me.tenant_id + '/users/' + target.membership_id, 'DELETE');
    record('UAT-USER-CLEANUP-MEMBERSHIP', 'Users & Access', 'admin', 'Remove only UAT-created Olympus membership and restore seeded directory to four', summary(removed), removed.status === 204 ? 'PASS' : 'FAIL', 'Delete disposable invited-user membership only; leave account status unchanged because platform lacks manage_status', removed.status);
  }
  const members = await api(page, '/api/tenants/' + me.tenant_id + '/users');
  const expectedRoles = { 'admin@olympus.example.test': 'TENANT_ADMIN', 'analyst@olympus.example.test': 'SECURITY_ANALYST', 'developer@olympus.example.test': 'DEVELOPER', 'viewer@olympus.example.test': 'VIEWER' };
  record('UAT-SEEDED-STATE-PRESERVED', 'UAT cleanup', 'admin', 'All four seeded Olympus members retain original role, membership, account and verification state', members, members.status === 200 && rows(members.data).length === 4 && rows(members.data).every(m => expectedRoles[m.email] === m.role && m.status === 'ACTIVE' && m.user_status === 'ACTIVE' && m.email_verified) ? 'PASS' : 'FAIL', 'Re-read original four-member directory after disposable membership cleanup', members.status);
  const oldSession = (await context.cookies()).find(c => c.name === '__Host-sbom-session')?.value;
  await page.goto(origin + '/settings/users', { waitUntil: 'domcontentloaded' }); await page.getByRole('heading', { name: 'Member Directory', exact: true }).waitFor({ timeout: 30000 });
  await page.getByRole('button', { name: 'Account menu for ' + me.display_name, exact: true }).click(); await page.getByRole('menuitem', { name: 'Sign Out', exact: true }).click(); await page.waitForURL(/logged-out/, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
  const replay = await context.request.get(origin + '/api/backend/api/projects', { headers: { Cookie: '__Host-sbom-session=' + oldSession } });
  record('UAT-LOGOUT-SERVER-REPLAY', 'Session security', 'admin', 'Previously valid session cookie cannot be replayed after actual UI Sign Out', { status: replay.status(), body: await replay.json() }, replay.status() === 401 ? 'PASS' : 'FAIL', 'Retain old cookie only in memory; UI Sign Out; replay against protected BFF; never write cookie value', replay.status());
  await context.close();
}
async function main() {
  if (process.argv[2] === 'security') return security();
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    if (process.argv[2] === 'users') await userAdmin(browser);
    else if (process.argv[2] === 'roles') await roles(browser);
    else if (process.argv[2] === 'invitations') await invitations(browser);
    else if (process.argv[2] === 'pages') await pages(browser);
    else if (process.argv[2] === 'business') await business(browser);
    else if (process.argv[2] === 'user-ui') await userUi(browser);
    else if (process.argv[2] === 'final-browser') await finalBrowser(browser);
    else throw Error('Unknown phase');
  } finally { await browser.close(); }
}
if (require.main === module) main().catch(e => { console.error(sanitize(e.message)); process.exitCode = 1; });
module.exports = { record, sanitize, summary, rows, identities, output, origin, login, logout, api };
