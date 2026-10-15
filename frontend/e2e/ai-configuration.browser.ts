import { resolve } from 'node:path';
import { test, expect, type Page } from '@playwright/test';

// All API calls are mocked. These tests never use saved credentials or live inference.
async function fixture(page: Page, readOnly = false) {
  const permissions = [
    'platform:ai:read',
    ...(readOnly ? [] : ['platform:ai:update', 'platform:ai:test']),
  ];
  const credential = {
    id: 1,
    provider_name: 'gemini',
    label: 'Primary',
    api_key_present: true,
    api_key_preview: null,
    base_url: null,
    default_model: 'gemma-test',
    tier: 'free',
    is_default: true,
    is_fallback: false,
    enabled: true,
    is_local: false,
    cost_per_1k_input_usd: 0,
    cost_per_1k_output_usd: 0,
    max_concurrent: 1,
    rate_per_minute: 15,
    created_at: '2026-10-15T10:00:00Z',
    updated_at: '2026-10-15T10:00:00Z',
    last_test_at: '2026-10-15T10:00:00Z',
    last_test_success: true,
    last_test_error: null,
  };
  const model = {
    id: 7,
    provider_credential_id: 1,
    provider_name: 'gemini',
    runtime_model_id: 'gemma-test-next',
    provider_model_id: 'models/gemma-test-next',
    display_name: 'Gemma Test Next',
    is_available: true,
    is_enabled: true,
    is_selected: false,
    supports_chat: true,
    supports_streaming: true,
    supports_tools: null,
    supports_structured_output: false,
    context_window: 262144,
    max_output_tokens: 8192,
    discovery_source: 'live',
    first_discovered_at: null,
    last_discovered_at: '2026-10-15T10:00:00Z',
    last_verified_at: null,
    last_test_success: null,
    last_test_error: null,
  };
  const catalog = [
    {
      name: 'gemini',
      display_name: 'Google Gemini',
      requires_api_key: true,
      requires_base_url: false,
      is_local: false,
      supports_free_tier: true,
      free_tier_rate_limit_rpm: 15,
      free_tier_daily_token_limit: null,
      available_models: [
        {
          name: 'gemma-test',
          display_name: 'Gemma Test',
          default_tier: 'free',
          notes: '',
        },
      ],
      docs_url: '',
      api_key_url: '',
      notes: '',
    },
  ];
  const writes: string[] = [];
  await page.context().addCookies([
    {
      name: '__Host-sbom-session',
      value: 'ai-ui-fixture-only',
      url: test.info().project.use.baseURL as string,
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
    },
  ]);
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown = {};
    if (request.method() !== 'GET') writes.push(`${request.method()} ${path}`);
    if (path === '/api/auth/session')
      body = { authenticated: true, provider: 'NATIVE' };
    else if (path.endsWith('/api/auth/me'))
      body = {
        user_id: 1,
        display_name: 'Fixture Admin',
        email: 'fixture@example.test',
        is_platform_admin: true,
        tenant_id: null,
        roles: ['PLATFORM_ADMIN'],
        permissions,
      };
    else if (path.endsWith('/effective-config'))
      body = {
        source: 'PLATFORM_DEFAULT',
        override_enabled: false,
        feature_enabled: true,
        default_selection_key: 'saved:1',
        configured_providers: [
          {
            ...credential,
            model: credential.default_model,
            credential_present: true,
            selection_key: 'saved:1',
          },
        ],
      };
    else if (path.endsWith('/providers/available')) body = catalog;
    else if (path.endsWith('/credentials/1/models/refresh'))
      body = { discovered: 1, created: 0, updated: 1, unavailable: 0 };
    else if (path.endsWith('/credentials/1/models/7/select')) {
      model.is_selected = true;
      credential.default_model = model.runtime_model_id;
      body = model;
    } else if (path.endsWith('/credentials/1/models/7/test'))
      body = { success: true, error_message: null };
    else if (path.endsWith('/credentials/1/models')) body = [model];
    else if (path.endsWith('/credentials/1/test'))
      body = {
        success: true,
        latency_ms: 10,
        detected_models: [],
        error_message: null,
        error_kind: null,
        provider: 'gemini',
        model: credential.default_model,
      };
    else if (path.endsWith('/credentials')) body = [credential];
    else if (path.endsWith('/settings'))
      body = {
        feature_enabled: true,
        kill_switch_active: false,
        budget_per_request_usd: 0.1,
        budget_per_scan_usd: 5,
        budget_daily_usd: 5,
        updated_at: '2026-10-15T10:00:00Z',
        updated_by_user_id: null,
        source: 'DB',
      };
    else if (/tenants|sboms|batches/.test(path)) body = [];
    await route.fulfill({ json: body });
  });
  return writes;
}

test('connection → discovery → model test → activation → reload', async ({
  page,
}) => {
  const writes = await fixture(page);
  await page.goto('/platform/configuration/ai');
  await expect(
    page.getByRole('heading', { name: 'AI Configuration', exact: true }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Test connection for Google Gemini' })
    .click();
  await page.getByRole('button', { name: 'Manage models' }).click();
  await page.getByRole('button', { name: 'Refresh models' }).click();
  await page.getByRole('button', { name: 'Test', exact: true }).click();
  await expect(page.getByText(/Model test passed/)).toBeVisible();
  await page.getByRole('button', { name: 'Set active' }).click();
  await expect(page.getByRole('dialog')).toContainText('tenants that inherit');
  await page.getByRole('button', { name: 'Confirm activation' }).click();
  await expect(
    page.getByRole('button', { name: 'Active', exact: true }),
  ).toBeDisabled();
  await page.reload();
  await expect(
    page.getByRole('region', { name: 'Effective configuration' }),
  ).toContainText('gemma-test-next');
  await page.getByRole('tab', { name: 'Models', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Active', exact: true }),
  ).toBeDisabled();
  expect(writes).toEqual(
    expect.arrayContaining([
      'POST /api/backend/api/platform/configuration/ai/credentials/1/test',
      'POST /api/backend/api/platform/configuration/ai/credentials/1/models/refresh',
      'POST /api/backend/api/platform/configuration/ai/credentials/1/models/7/test',
      'POST /api/backend/api/platform/configuration/ai/credentials/1/models/7/select',
    ]),
  );
});

test('read-only platform access exposes safe details without mutations', async ({
  page,
}) => {
  const writes = await fixture(page, true);
  await page.goto('/platform/configuration/ai');
  await expect(
    page.getByText('Read-only access.', { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Add provider', exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Test connection for Google Gemini' }),
  ).toBeDisabled();
  await page.getByRole('button', { name: 'Manage models' }).click();
  await expect(page.getByRole('button', { name: 'Set active' })).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Test', exact: true }),
  ).toBeDisabled();
  expect(writes).toEqual([]);
});

test('responsive views, dark theme, large text and dialog keyboard access', async ({
  page,
}) => {
  await fixture(page);
  await page.goto('/platform/configuration/ai');
  await expect(
    page.getByRole('button', { name: 'Manage models' }),
  ).toBeVisible();
  for (const width of [1440, 1024, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    for (const name of ['Providers', 'Models', 'Defaults & Overrides']) {
      await page.getByRole('tab', { name, exact: true }).click();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth + 1,
        ),
      ).toBe(true);
    }
  }
  await page.evaluate(() => document.documentElement.classList.add('dark'));
  await page.getByRole('tab', { name: 'Providers', exact: true }).click();
  await page.screenshot({
    path: '/tmp/sbom-ai-ui/mobile-dark.png',
    fullPage: true,
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.waitForFunction(
    () =>
      (document.querySelector('#main-content')?.getBoundingClientRect().left ??
        0) >= 239,
  );
  await page.evaluate(() => document.documentElement.classList.remove('dark'));
  await page.screenshot({
    path: '/tmp/sbom-ai-ui/desktop-providers.png',
    fullPage: true,
  });
  await page.getByRole('tab', { name: 'Models', exact: true }).click();
  await page.getByText('Capabilities and details').click();
  await page.screenshot({
    path: '/tmp/sbom-ai-ui/desktop-models.png',
    fullPage: true,
  });
  await page.evaluate(() => {
    document.documentElement.style.fontSize = '200%';
  });
  await page.setViewportSize({ width: 720, height: 900 });
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth + 1,
      ),
    )
    .toBe(true);
  await page.getByRole('button', { name: 'Add provider', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole('button', { name: 'Close dialog' }),
  ).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  // The required key is blank, so Save is disabled; Cancel is the last focusable control.
  await expect(
    dialog.getByRole('button', { name: 'Cancel', exact: true }),
  ).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Add provider', exact: true }),
  ).toBeFocused();
});

test('AI views meet text contrast checks in light and dark themes', async ({
  page,
}) => {
  await fixture(page);
  await page.goto('/platform/configuration/ai');
  await expect(
    page.getByRole('button', { name: 'Manage models' }),
  ).toBeVisible();
  await page.addScriptTag({
    path: resolve(__dirname, '../node_modules/axe-core/axe.min.js'),
  });
  for (const dark of [false, true]) {
    await page.evaluate(
      (value) => document.documentElement.classList.toggle('dark', value),
      dark,
    );
    for (const name of ['Providers', 'Models', 'Defaults & Overrides']) {
      await page.getByRole('tab', { name, exact: true }).click();
      const violations = await page.evaluate(async () => {
        const axe = (
          window as typeof window & {
            axe: {
              run: (
                context: Element,
                options: unknown,
              ) => Promise<{
                violations: { id: string; nodes: { html: string }[] }[];
              }>;
            };
          }
        ).axe;
        return (
          await axe.run(
            document.querySelector('[aria-label="AI Configuration"]')!,
            { runOnly: ['color-contrast'] },
          )
        ).violations;
      });
      expect(violations).toEqual([]);
    }
  }
});
