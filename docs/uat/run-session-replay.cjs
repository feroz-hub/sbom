/* Real Chrome logout/replay check. Secret values never enter evidence. */
const { chromium } = require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const { login, api, record, sanitize, origin } = require('./run-role-uat.cjs');
async function main() {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  let session;
  try {
    session = await login(browser, 'admin');
    const { page, context } = session;
    const previous = (await context.cookies()).find(c => c.name === '__Host-sbom-session');
    if (!previous) throw new Error('Authenticated session cookie was not present');
    const before = await api(page, '/api/projects');
    await page.getByRole('button', { name: /^Account menu for / }).click();
    const signout = page.waitForResponse(r => r.url().includes('/api/auth/logout') && r.request().method() === 'POST');
    await page.getByRole('menuitem', { name: 'Sign Out', exact: true }).click();
    const response = await signout;
    const replay = await context.request.get(origin + '/api/backend/api/projects', {
      headers: { Cookie: previous.name + '=' + previous.value }, timeout: 20000,
    });
    const cookies = await context.cookies();
    record('UAT-LOGOUT-SERVER-REPLAY', 'Session security', 'admin',
      'Previously valid cookie is rejected after actual UI Sign Out',
      { authenticatedBefore: before.status, logoutStatus: response.status(), replayStatus: replay.status(), sessionCookiePresent: cookies.some(c => c.name === previous.name) },
      before.status === 200 && response.ok() && replay.status() === 401 && !cookies.some(c => c.name === previous.name) ? 'PASS' : 'FAIL',
      'Fresh isolated Native Login; protected API succeeds; UI Sign Out; replay old cookie held only in memory; verify 401 and cookie removal', replay.status());
  } catch (error) {
    record('UAT-LOGOUT-SERVER-REPLAY', 'Session security', 'admin', 'Previously valid cookie is rejected after actual UI Sign Out',
      { error: sanitize(error.message) }, 'BLOCKED', 'Run real Chrome logout and replay; record only sanitized error if prerequisite unavailable', null, 'ENV-001');
    process.exitCode = 1;
  } finally {
    if (session) await session.context.close();
    await browser.close();
  }
}
main();
