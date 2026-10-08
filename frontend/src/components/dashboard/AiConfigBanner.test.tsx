// @vitest-environment jsdom
import { render, screen, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiConfigBanner } from './AiConfigBanner';
import { getAnalysisConfig, type EffectiveAiStatus } from '@/lib/api';
vi.mock('@/lib/api', () => ({ getAnalysisConfig: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: '1', isPlatformContext: false }) }));
const base: EffectiveAiStatus = { configured: true, source: 'PLATFORM', provider: 'gemini', model: 'test', verification_status: 'VERIFIED', feature_enabled: true, available_for_tenant: true, state: 'AVAILABLE', can_view_settings: true, can_configure: true, settings_scope: 'tenant' };
let client: QueryClient;
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
    await screen.findByText('AI configuration required'); expect(screen.queryByRole('link')).not.toBeInTheDocument();
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
