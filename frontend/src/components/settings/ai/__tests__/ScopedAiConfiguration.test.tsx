// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ScopedAiConfiguration } from '../ScopedAiConfiguration';
import { navigationItems } from '@/lib/navigation';

const state = vi.hoisted(() => ({ permissions: [] as string[], activeTenantId: null as string | null, overridden: false }));
const api = vi.hoisted(() => ({ getEffectiveAiConfiguration: vi.fn(), createTenantAiOverride: vi.fn(), resetTenantAiOverride: vi.fn() }));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: 1, permissions: [] }, isLoading: false, activeTenantId: state.activeTenantId, activeTenant: state.activeTenantId ? { name: 'Olympus' } : null, hasPermission: (permission: string) => state.permissions.includes(permission) }) }));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title, subtitle }: { title: string; subtitle: string }) => <header>{title} · {subtitle}</header> }));
vi.mock('../AiSettingsPage', () => ({ AiSettingsPage: () => <p>Owned configuration editor</p> }));

function mount(scope: 'platform' | 'tenant') {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ScopedAiConfiguration scope={scope} /></QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  state.permissions = ['tenant:ai:read', 'tenant:ai:update', 'tenant:ai:test'];
  state.activeTenantId = '1';
  state.overridden = false;
  api.getEffectiveAiConfiguration.mockImplementation(async () => ({ source: state.overridden ? 'TENANT_OVERRIDE' : 'PLATFORM_DEFAULT', override_enabled: state.overridden, feature_enabled: true, configured_providers: [{ provider_name: 'openai', model: 'safe-model', enabled: true, credential_present: true }] }));
  api.createTenantAiOverride.mockImplementation(async () => { state.overridden = true; });
  api.resetTenantAiOverride.mockImplementation(async () => { state.overridden = false; });
});

describe('configuration ownership', () => {
  it('tenant inheritance shows safe platform metadata without an editor or secret', async () => {
    mount('tenant');
    expect(await screen.findByText('Platform default')).toBeInTheDocument();
    expect(screen.getByText('Olympus is using the platform default.')).toBeInTheDocument();
    expect(screen.getByText('Credential managed by platform')).toBeInTheDocument();
    expect(screen.queryByText('Owned configuration editor')).not.toBeInTheDocument();
    expect(api.getEffectiveAiConfiguration).toHaveBeenCalledWith('tenant', expect.any(AbortSignal));
  });

  it('override and reset change only the tenant source', async () => {
    mount('tenant');
    await userEvent.click(await screen.findByRole('button', { name: 'Override for Olympus' }));
    expect(await screen.findByText('Tenant override active')).toBeInTheDocument();
    expect(screen.getByText('Owned configuration editor')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Reset to Platform Default' }));
    expect(await screen.findByText('Platform default')).toBeInTheDocument();
    expect(api.createTenantAiOverride).toHaveBeenCalledTimes(1);
    expect(api.resetTenantAiOverride).toHaveBeenCalledTimes(1);
  });

  it('platform context edits defaults and has no tenant override actions', async () => {
    state.activeTenantId = null;
    state.permissions = ['platform:ai:read', 'platform:ai:update', 'platform:ai:test'];
    mount('platform');
    expect(await screen.findByText('Owned configuration editor')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Override for/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Reset to/ })).not.toBeInTheDocument();
    expect(api.getEffectiveAiConfiguration).toHaveBeenCalledWith('platform', expect.any(AbortSignal));
  });

  it('dual-role identity in tenant context cannot open the platform editor', async () => {
    mount('platform');
    expect(screen.getByRole('alert')).toHaveTextContent('not permitted');
    await waitFor(() => expect(api.getEffectiveAiConfiguration).not.toHaveBeenCalled());
  });

  it('read-only tenant configuration does not expose override actions', async () => {
    state.permissions = ['tenant:ai:read'];
    mount('tenant');
    await screen.findByText('Platform default');
    expect(screen.queryByRole('button', { name: /Override for/ })).not.toBeInTheDocument();
  });

  it('navigation exposes configuration only in the matching active permission scope', () => {
    const items = navigationItems.flatMap(item => item.children ?? [item]);
    const visible = (permissions: string[]) => items.filter(item => item.permission && permissions.includes(item.permission));
    expect(visible(['platform:ai:read', 'platform:lifecycle-provider:read']).map(item => item.href)).toEqual(['/platform/configuration/ai', '/platform/configuration/lifecycle']);
    expect(visible(['tenant:ai:read', 'tenant:lifecycle-provider:read']).map(item => item.href)).toEqual(['/settings/ai', '/admin/lifecycle-providers']);
  });
});
