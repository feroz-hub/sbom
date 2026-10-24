// @vitest-environment jsdom
import { render, screen, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AiConfigBanner } from './AiConfigBanner';
import { getAnalysisConfig, type EffectiveAiStatus } from '@/lib/api';
vi.mock('@/lib/api', () => ({ getAnalysisConfig: vi.fn() }));
const auth = vi.hoisted(() => ({ activeTenantId: '1', isPlatformContext: false, isLoading: false, user: { userId: 8, permissions: ['tenant:ai:read', 'tenant:ai:update'] } }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => auth }));
const base: EffectiveAiStatus = { configured: true, source: 'PLATFORM', provider: 'gemini', model: 'test', verification_status: 'VERIFIED', feature_enabled: true, available_for_tenant: true, state: 'AVAILABLE', can_view_settings: true, can_configure: true, settings_scope: 'tenant' };
let client: QueryClient;
beforeEach(() => { auth.activeTenantId = '1'; auth.user = { userId: 8, permissions: ['tenant:ai:read', 'tenant:ai:update'] }; vi.clearAllMocks(); });
function show(changes: Partial<EffectiveAiStatus> = {}) {
  vi.mocked(getAnalysisConfig).mockResolvedValue({ github_configured: false, nvd_key_configured: false, max_concurrency: 10, ai_status: { ...base, ...changes } });
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><AiConfigBanner /></QueryClientProvider>);
}
afterEach(() => { cleanup(); client?.clear(); });
describe('effective AI dashboard status', () => {
  it('shows platform inheritance and settings link', async () => {
    show(); await screen.findByText('AI Fix Generation available');
    expect(screen.getByText(/Platform managed · Google Gemini · Available/)).toBeInTheDocument();
    expect(screen.getByRole('link')).toHaveAttribute('href', '/settings/ai');
    expect(screen.queryByText(/free tier|aren.t configured/)).not.toBeInTheDocument();
  });
  it('shows override and scope-correct platform settings route', async () => {
    show({ source: 'TENANT', provider: 'openai', settings_scope: 'platform' });
    await screen.findByText(/Tenant managed · OpenAI/);
    expect(screen.getByRole('link')).toHaveAttribute('href', '/platform/configuration/ai');
  });
  it.each([
    ['DISABLED', 'AI Fix Generation is disabled for this deployment.'],
    ['VERIFICATION_PENDING', 'AI provider configured'],
    ['TEMPORARILY_UNAVAILABLE', 'AI provider temporarily unavailable'],
    ['CONFIGURATION_UNAVAILABLE', 'AI configuration needs attention'],
    ['STATUS_UNAVAILABLE', 'AI status unavailable'],
  ] as const)('distinguishes %s from absent configuration', async (state, title) => {
    show({ state, available_for_tenant: false }); await screen.findByText(title);
    expect(screen.queryByText('AI configuration required')).not.toBeInTheDocument();
    expect(screen.queryByText(/· Available/)).not.toBeInTheDocument();
  });
  it('hides settings/configure actions for viewers', async () => {
    show({ configured: false, state: 'CONFIGURATION_REQUIRED', can_configure: false, can_view_settings: false });
    await screen.findByText('AI Fix Generation unavailable'); expect(screen.getByText(/Contact your Tenant Administrator/)).toBeInTheDocument(); expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
  it('offers configuration to authorized users', async () => {
    show({ configured: false, state: 'CONFIGURATION_REQUIRED' });
    expect(await screen.findByRole('link', { name: 'Configure AI' })).toBeInTheDocument();
  });
  it('updates after mutation invalidation', async () => {
    show(); await screen.findByText(/Platform managed/);
    vi.mocked(getAnalysisConfig).mockResolvedValue({ github_configured: false, nvd_key_configured: false, max_concurrency: 10, ai_status: { ...base, source: 'TENANT', provider: 'openai' } });
    await client.invalidateQueries({ queryKey: ['analysis-config'] });
    expect(await screen.findByText(/Tenant managed · OpenAI/)).toBeInTheDocument();
  });
});

it('explains empty tenant override to an administrator without suggesting another mandatory provider', async () => {
  show({ configured: false, source: 'TENANT', state: 'CONFIGURATION_REQUIRED', available_for_tenant: false });
  await screen.findByText('AI configuration needs attention');
  expect(screen.getByText(/restore platform inheritance/)).toBeInTheDocument();
  expect(screen.getByRole('link')).toHaveTextContent('View AI Settings');
  expect(screen.queryByRole('link', { name: 'Configure AI' })).not.toBeInTheDocument();
});

it('shows inherited availability to an analyst with no management action', async () => {
  auth.user = { userId: 2, permissions: [] };
  show({ can_configure: false, can_view_settings: false, can_invoke_ai: false });
  await screen.findByText('AI Fix Generation available');
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(screen.getByText(/current permissions do not allow AI Fix Generation/)).toBeInTheDocument();
});

it.each([
  [401, 'Authentication is required to check AI availability.'],
  [403, 'You are not authorized to view AI availability for this context.'],
  [404, 'AI status is not available from this deployment.'],
  [500, 'Unable to determine AI status. Try again later.'],
  [503, 'Unable to determine AI status. Try again later.'],
  [undefined, 'AI status is temporarily unavailable. Try again later.'],
])('does not infer missing provider from request failure %s', async (status, message) => {
  vi.mocked(getAnalysisConfig).mockRejectedValue(Object.assign(new Error('request failed'), { status }));
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><AiConfigBanner /></QueryClientProvider>);
  await screen.findByText(message);
  expect(screen.queryByText('AI configuration required')).not.toBeInTheDocument();
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
});

it('isolates cached management actions when the user changes in the same tenant', async () => {
  show(); await screen.findByRole('link', { name: 'View AI Settings' });
  auth.user = { userId: 2, permissions: [] };
  vi.mocked(getAnalysisConfig).mockResolvedValue({ github_configured: false, nvd_key_configured: false, max_concurrency: 10, ai_status: { ...base, can_configure: false, can_view_settings: false } });
  cleanup(); render(<QueryClientProvider client={client}><AiConfigBanner /></QueryClientProvider>);
  await screen.findByText('AI Fix Generation available');
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(getAnalysisConfig).toHaveBeenCalledTimes(2);
});

it('refetches for tenant and permission changes even when the user stays the same', async () => {
  show(); await screen.findByText(/Platform managed/);
  auth.activeTenantId = '2';
  vi.mocked(getAnalysisConfig).mockResolvedValue({ github_configured: false, nvd_key_configured: false, max_concurrency: 10, ai_status: { ...base, source: 'TENANT', provider: 'openai' } });
  cleanup(); render(<QueryClientProvider client={client}><AiConfigBanner /></QueryClientProvider>);
  await screen.findByText(/Tenant managed · OpenAI/);
  auth.user.permissions = [];
  vi.mocked(getAnalysisConfig).mockResolvedValue({ github_configured: false, nvd_key_configured: false, max_concurrency: 10, ai_status: { ...base, source: 'TENANT', provider: 'openai', can_view_settings: false, can_configure: false } });
  cleanup(); render(<QueryClientProvider client={client}><AiConfigBanner /></QueryClientProvider>);
  await screen.findByText(/Tenant managed · OpenAI/);
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(getAnalysisConfig).toHaveBeenCalledTimes(3);
});
