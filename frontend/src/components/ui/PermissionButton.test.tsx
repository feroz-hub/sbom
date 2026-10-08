// @vitest-environment jsdom
import { fireEvent, render, screen, renderHook } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionButton } from './PermissionButton';
import { PermissionFields, PermissionRouteGuard } from './PermissionGate';
import { PermissionLink } from './PermissionLink';
import { InventoryActionMenu } from '@/components/projects/InventoryActionMenu';
import { usePermissions } from '@/hooks/usePermission';
import catalogue from '@/test/permissionCatalogue.json';

const state = vi.hoisted(() => ({ permissions: [] as string[], roles: ['VIEWER'], loading: false, tenantLoading: false, error: false, path: '/projects' }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  user: { userId: 1, roles: state.roles, permissions: state.permissions },
  isLoading: state.loading, isTenantContextLoading: state.tenantLoading,
  bootstrapState: state.error ? 'error' : 'ready', bootstrapError: state.error ? 'Network failure' : null,
  hasPermission: (code: string) => state.permissions.includes(code),
}) }));
vi.mock('next/navigation', () => ({ usePathname: () => state.path }));
beforeEach(() => { Object.assign(state, { permissions: [], roles: ['VIEWER'], loading: false, tenantLoading: false, error: false, path: '/projects' }); });

describe('effective permission controls', () => {
  it.each(Object.entries(catalogue.roles))('%s follows the actual backend permission grants', (role, grants) => {
    state.roles = [role]; state.permissions = grants;
    render(<><PermissionButton permission="project:create">New Project</PermissionButton><PermissionButton permission="product:create">Create Application</PermissionButton><PermissionButton permission="analysis:run">Run Analysis</PermissionButton></>);
    for (const [name, permission] of [['New Project', 'project:create'], ['Create Application', 'product:create'], ['Run Analysis', 'analysis:run']]) {
      expect(screen.getByRole('button', { name })).toHaveProperty('disabled', !grants.includes(permission));
    }
  });
  it('does not infer authority from role names and supports effective multi-role grants', () => {
    state.roles = ['VIEWER', 'DEVELOPER']; state.permissions = ['project:create'];
    const { result } = renderHook(() => usePermissions());
    expect(result.current.can('project:create')).toBe(true); expect(result.current.can('project:delete')).toBe(false);
    state.roles = ['TENANT_ADMIN']; state.permissions = []; render(<PermissionButton permission="project:create">Create</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled();
  });
  it('does not execute forbidden click or keyboard activation and explains denial on focus', async () => {
    const open = vi.fn(); const user = userEvent.setup();
    render(<PermissionButton permission="project:create" onClick={open}>New Project</PermissionButton>);
    const button = screen.getByRole('button'); expect(button).toBeDisabled();
    fireEvent.click(button); await user.tab();
    expect(button.parentElement).toHaveFocus(); expect(button.parentElement).toHaveAccessibleDescription(/don't have permission to create projects/);
    await user.keyboard('{Enter} '); expect(open).not.toHaveBeenCalled();
  });
  it('keeps ordinary read and filter actions enabled', () => {
    render(<PermissionButton onClick={vi.fn()}>View project</PermissionButton>); expect(screen.getByRole('button')).toBeEnabled();
  });
  it.each(['loading', 'tenantLoading'] as const)('fails closed during %s without flashing authorized actions', flag => {
    state.permissions = ['project:create']; state[flag] = true;
    const { rerender } = render(<PermissionButton permission="project:create">Create</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled(); expect(screen.getByRole('button').parentElement).toHaveAccessibleDescription('Checking your permissions…');
    state[flag] = false; rerender(<PermissionButton permission="project:create">Create</PermissionButton>); expect(screen.getByRole('button')).toBeEnabled();
  });
  it('reports permission resolution failure without claiming a definitive denial', () => {
    state.error = true; render(<PermissionButton permission="project:create">Create</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled(); expect(screen.getByRole('button').parentElement).toHaveAccessibleDescription(/Unable to verify access/);
  });
  it('updates action availability when tenant permissions change', () => {
    state.permissions = ['project:create']; const { rerender } = render(<PermissionButton permission="project:create">Create</PermissionButton>);
    expect(screen.getByRole('button')).toBeEnabled(); state.permissions = ['project:read']; rerender(<PermissionButton permission="project:create">Create</PermissionButton>); expect(screen.getByRole('button')).toBeDisabled();
  });
  it('requires every endpoint permission, including assignment dependencies', () => {
    state.permissions = ['sbom:upload']; render(<PermissionButton permission={['sbom:upload', 'product:assign_sbom']}>Upload</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled();
  });
  it('preserves backend resource capabilities and business-state restrictions', () => {
    state.permissions = ['vex:read']; const save = vi.fn();
    const { rerender } = render(<PermissionButton resourceAllowed={true} onClick={save}>Save decision</PermissionButton>);
    fireEvent.click(screen.getByRole('button')); expect(save).toHaveBeenCalledOnce();
    rerender(<PermissionButton resourceAllowed={false} disabledReason="This investigation is not assigned to you." onClick={save}>Save decision</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled(); expect(screen.getByRole('button').parentElement).toHaveAccessibleDescription(/not assigned/);
    state.permissions = ['sbom:repair:revalidate']; rerender(<PermissionButton permission="sbom:repair:revalidate" disabled disabledReason="Validation must pass before import." onClick={save}>Import</PermissionButton>);
    expect(screen.getByRole('button')).toBeDisabled(); expect(screen.getByRole('button').parentElement).toHaveAccessibleDescription(/Validation must pass/);
  });
  it('makes mutation forms read-only and blocks implicit submission', () => {
    const submit = vi.fn(); render(<PermissionFields permission="project:create"><form onSubmit={submit}><input aria-label="Name" /><button type="submit">Save</button></form></PermissionFields>);
    expect(screen.getByRole('textbox')).toBeDisabled(); fireEvent.submit(screen.getByRole('textbox').closest('form')!); expect(submit).not.toHaveBeenCalled();
  });
  it('blocks unauthorized links and menu activation, including keyboard clicks', async () => {
    const edit = vi.fn(); render(<><PermissionLink permission="sbom:upload" href="/sboms?action=upload">Upload</PermissionLink><InventoryActionMenu label="Actions" actions={[{ label: 'View', href: '/projects' }, { label: 'Edit', onClick: edit, permission: 'project:update' }, { label: 'Upload', href: '/sboms?action=upload', permission: 'sbom:upload' }]} /></>);
    expect(screen.queryByRole('link', { name: 'Upload' })).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Actions' }));
    expect(screen.getByRole('menuitem', { name: 'View' })).toHaveAttribute('href');
    const forbidden = screen.getByRole('menuitem', { name: 'Edit' }); expect(forbidden).toHaveAttribute('aria-disabled', 'true'); expect(forbidden).toHaveAccessibleDescription(/permission/);
    forbidden.focus(); await userEvent.setup().keyboard('{Enter} '); expect(edit).not.toHaveBeenCalled();
    expect(screen.getByRole('menuitem', { name: 'Upload' })).not.toHaveAttribute('href');
  });
  it('does not mount privileged forms on direct route entry', () => {
    state.path = '/platform/configuration/ai'; const mounted = vi.fn(); function Form() { mounted(); return <input />; }
    render(<PermissionRouteGuard><Form /></PermissionRouteGuard>); expect(screen.getByRole('heading', { name: 'Access restricted' })).toBeInTheDocument(); expect(mounted).not.toHaveBeenCalled(); expect(screen.getByRole('link', { name: 'Back to Dashboard' })).toHaveAttribute('href', '/');
  });
  it('permits authorized read-only routes', () => {
    state.permissions = ['project:read']; render(<PermissionRouteGuard><h1>Project inventory</h1></PermissionRouteGuard>); expect(screen.getByRole('heading', { name: 'Project inventory' })).toBeInTheDocument();
  });
});

it('renders disabled explanations outside clipping containers and dismisses them with Escape', async () => {
  render(<div style={{ overflow: 'hidden' }}><PermissionButton permission="project:create">New Project</PermissionButton></div>);
  await userEvent.setup().tab();
  const tooltip = screen.getByRole('tooltip'); expect(tooltip).toBeVisible(); expect(tooltip.parentElement).toBe(document.body);
  await userEvent.setup().keyboard('{Escape}'); expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
});

it.each(Object.entries(catalogue.roles))('%s retains its exact capabilities across major modules', (role, grants) => {
  state.roles = [role]; state.permissions = grants;
  const controls = ['sbom:upload', 'sbom:delete', 'sbom:export', 'sbom:repair:update', 'sbom:repair:revalidate', 'sbom:repair:download', 'analysis:run', 'remediation:write', 'schedule:write', 'component_advisor:recommendation:create', 'tenant:ai:update', 'tenant:user:invite', 'platform:ai:update'];
  render(<>{controls.map(permission => <PermissionButton key={permission} permission={permission}>{permission}</PermissionButton>)}</>);
  for (const permission of controls) expect(screen.getByRole('button', { name: permission })).toHaveProperty('disabled', !grants.includes(permission));
});
