// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ScopedLifecycleConfiguration } from './ScopedLifecycleConfiguration';

const state = vi.hoisted(() => ({ permissions: [] as string[], tenantId: null as string | null }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: '00000000-0000-4000-8000-000000000001', permissions: [] },
  isLoading: false,
  activeTenantId: state.tenantId,
  activeTenant: state.tenantId ? { name: 'Olympus' } : null,
  hasPermission: (permission: string) => state.permissions.includes(permission),
}) }));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ subtitle }: { subtitle: string }) => <p>{subtitle}</p> }));
vi.mock('./LifecycleProviderSettings', () => ({ LifecycleProviderSettings: ({ scope, canUpdate }: { scope: string; canUpdate: boolean }) => (
  <p>Configuration editor: {scope}, {canUpdate ? 'editable' : 'read only'}</p>
) }));

beforeEach(() => { state.permissions = []; state.tenantId = null; });

describe('lifecycle configuration active-context boundary', () => {
  it('platform permissions expose only platform defaults', () => {
    state.permissions = ['platform:lifecycle-provider:read', 'platform:lifecycle-provider:update'];
    render(<ScopedLifecycleConfiguration scope="platform" />);
    expect(screen.getByText('Platform defaults')).toBeInTheDocument();
    expect(screen.getByText('Manage component lifecycle intelligence sources and their operational configuration.')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Configuration scope' })).toHaveTextContent('Existing tenant overrides retain their own configuration');
    expect(screen.getByText('Configuration editor: platform, editable')).toBeInTheDocument();
  });

  it('tenant permissions expose only the named tenant editor', () => {
    state.tenantId = '1';
    state.permissions = ['tenant:lifecycle-provider:read', 'tenant:lifecycle-provider:update'];
    render(<ScopedLifecycleConfiguration scope="tenant" />);
    expect(screen.getByText('Tenant configuration · Olympus')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Configuration scope' })).toHaveTextContent('Providers inherit platform settings unless customized here');
    expect(screen.getByRole('link', { name: 'About lifecycle sources' })).toHaveAttribute('href', '#lifecycle-help');
    expect(screen.getByText('Configuration editor: tenant, editable')).toBeInTheDocument();
  });

  it('a dual-role user in tenant context cannot use platform configuration permissions', () => {
    state.tenantId = '1';
    state.permissions = ['tenant:lifecycle-provider:read'];
    render(<ScopedLifecycleConfiguration scope="platform" />);
    expect(screen.getByRole('alert')).toHaveTextContent('not permitted');
    expect(screen.queryByText(/Configuration editor/)).not.toBeInTheDocument();
  });

  it('read permission does not expose mutation controls', () => {
    state.tenantId = '1';
    state.permissions = ['tenant:lifecycle-provider:read'];
    render(<ScopedLifecycleConfiguration scope="tenant" />);
    expect(screen.getByText('Configuration editor: tenant, read only')).toBeInTheDocument();
  });
});
