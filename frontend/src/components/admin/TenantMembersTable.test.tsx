// @vitest-environment jsdom
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TenantMembersTable } from './TenantMembersTable';
import type { TenantMember } from '@/lib/api';

const member: TenantMember = {
  membership_id: 1, user_id: '00000000-0000-4000-8000-000000000002', external_iam_user_id: 'example-subject', display_name: 'Example Member', email: 'member@example.test',
  user_status: 'SUSPENDED', email_verified: true, verification_required: false,
  role: 'VIEWER', roles: ['VIEWER', 'DEVELOPER'], status: 'DISABLED', role_assignment_version: 1,
};
function props() {
  return { members: [member], isLoading: false, error: null, canUpdate: true,
    onManageRoles: vi.fn(), onDisableMembership: vi.fn(), onEnableMembership: vi.fn(), onRemoveFromTenant: vi.fn() };
}

describe('Shared TenantMembersTable', () => {
  it('preserves the default consumer contract and distinct security states in table and mobile cards', () => {
    render(<TenantMembersTable {...props()} />);
    expect(screen.getByRole('heading', { name: 'Tenant Members' })).toBeInTheDocument();
    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('columnheader').map(header => header.textContent)).toEqual(['User', 'Verification', 'Effective roles', 'Membership', 'User account', 'Actions']);
    expect(screen.getAllByText('Verification: Verified')).toHaveLength(2);
    expect(screen.getAllByText('No effective roles')).toHaveLength(2);
    expect(screen.getAllByText(/Assigned roles: Viewer, Developer/)).toHaveLength(2);
    expect(screen.getAllByText('User account: Suspended')).toHaveLength(2);
    expect(within(table).getByText('Disabled')).toBeInTheDocument();
    expect(screen.getByText('Membership: Disabled')).toBeInTheDocument();
  });
  it('retains member callbacks with the original member object', async () => {
    const handlers = props();
    render(<TenantMembersTable {...handlers} />);
    const user = userEvent.setup();
    await user.click(within(screen.getByRole('table')).getByRole('button', { name: 'Open actions for Example Member' }));
    await user.click(screen.getByRole('menuitem', { name: 'Enable membership' }));
    expect(handlers.onEnableMembership).toHaveBeenCalledWith(member);
  });
  it('keeps data visible without mutation controls for read-only consumers', () => {
    render(<TenantMembersTable {...props()} canUpdate={false} />);
    expect(screen.getAllByText('Example Member')).toHaveLength(2);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
  it('shows a fetch failure instead of presenting stale rows as current data', () => {
    render(<TenantMembersTable {...props()} error={new Error('offline')} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText('Example Member')).not.toBeInTheDocument();
  });
});
