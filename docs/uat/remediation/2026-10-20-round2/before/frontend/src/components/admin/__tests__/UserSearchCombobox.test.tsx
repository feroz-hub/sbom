// @vitest-environment jsdom

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserSearchResult } from '@/lib/api';
import { ApiError } from '@/lib/api';

const searchTenantUserCandidatesMock = vi.hoisted(() => vi.fn());
const searchPlatformUsersMock = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    searchTenantUserCandidates: searchTenantUserCandidatesMock,
    searchPlatformUsers: searchPlatformUsersMock,
  };
});

import { UserSearchCombobox } from '../UserSearchCombobox';

const ferozeCandidate: UserSearchResult = {
  id: 10,
  email: 'ferozebasha.s@hcltech.com',
  display_name: 'Feroze Basha',
  username: 'feroze',
  status: 'ACTIVE',
  email_verified: true,
  verification_required: false,
  external_subject: 'feroze-sub',
  tenant_membership: null,
};

describe('UserSearchCombobox component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('passing tenantId calls searchTenantUserCandidates and does not call searchPlatformUsers', async () => {
    searchTenantUserCandidatesMock.mockResolvedValue([ferozeCandidate]);

    render(<UserSearchCombobox tenantId={7} onSelect={vi.fn()} selectedUser={null} />);

    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'feroze' } });

    await waitFor(() => expect(searchTenantUserCandidatesMock).toHaveBeenCalledTimes(1));
    expect(searchTenantUserCandidatesMock).toHaveBeenCalledWith(7, 'feroze');
    expect(searchPlatformUsersMock).not.toHaveBeenCalled();

    expect(await screen.findByText('Feroze Basha')).toBeInTheDocument();
  });

  it('displays candidate from another tenant (Feroze)', async () => {
    searchTenantUserCandidatesMock.mockResolvedValue([ferozeCandidate]);

    render(<UserSearchCombobox tenantId={7} onSelect={vi.fn()} selectedUser={null} />);

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'feroze' } });

    expect(await screen.findByText('Feroze Basha')).toBeInTheDocument();
    expect(screen.getByText('ferozebasha.s@hcltech.com')).toBeInTheDocument();
  });

  it('excludes existing selected-tenant member based on backend response returning empty list', async () => {
    searchTenantUserCandidatesMock.mockResolvedValue([]);

    render(<UserSearchCombobox tenantId={7} onSelect={vi.fn()} selectedUser={null} />);

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'existing.member' } });

    expect(await screen.findByText('No eligible users found for this tenant.')).toBeInTheDocument();
  });

  it('displays correct safe message on 401, 403, 404, and generic errors', async () => {
    const onSelect = vi.fn();

    // 401 error
    searchTenantUserCandidatesMock.mockRejectedValueOnce(new ApiError('Unauthorized', 401));
    const { unmount: u1 } = render(<UserSearchCombobox tenantId={7} onSelect={onSelect} selectedUser={null} />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'test' } });
    expect(await screen.findByText('Your session has expired. Sign in again.')).toBeInTheDocument();
    u1();

    // 403 error
    searchTenantUserCandidatesMock.mockRejectedValueOnce(new ApiError('Forbidden', 403));
    const { unmount: u2 } = render(<UserSearchCombobox tenantId={7} onSelect={onSelect} selectedUser={null} />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'test' } });
    expect(await screen.findByText('You do not have permission to add members to this tenant.')).toBeInTheDocument();
    u2();

    // 404 error
    searchTenantUserCandidatesMock.mockRejectedValueOnce(new ApiError('Not found', 404));
    const { unmount: u3 } = render(<UserSearchCombobox tenantId={7} onSelect={onSelect} selectedUser={null} />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'test' } });
    expect(await screen.findByText('The selected tenant could not be found.')).toBeInTheDocument();
    u3();

    // 500 error
    searchTenantUserCandidatesMock.mockRejectedValueOnce(new Error('Network error'));
    render(<UserSearchCombobox tenantId={7} onSelect={onSelect} selectedUser={null} />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'test' } });
    expect(await screen.findByText('User search could not be completed. Try again.')).toBeInTheDocument();
  });

  it('prevents stale search responses from overwriting newer query results', async () => {
    let resolveFirst: (value: UserSearchResult[]) => void = () => {};
    const firstPromise = new Promise<UserSearchResult[]>((res) => {
      resolveFirst = res;
    });

    searchTenantUserCandidatesMock.mockImplementation((_tenantId, query) => {
      if (query === 'fer') return firstPromise;
      if (query === 'feroze') return Promise.resolve([ferozeCandidate]);
      return Promise.resolve([]);
    });

    render(<UserSearchCombobox tenantId={7} onSelect={vi.fn()} selectedUser={null} />);

    const input = screen.getByRole('textbox');

    // First query "fer"
    fireEvent.change(input, { target: { value: 'fer' } });

    // Fast follow-up query "feroze"
    fireEvent.change(input, { target: { value: 'feroze' } });

    // Wait for second query results to render
    expect(await screen.findByText('Feroze Basha')).toBeInTheDocument();

    // Now resolve first query with stale result
    const staleUser: UserSearchResult = { ...ferozeCandidate, id: 99, display_name: 'Stale User' };
    resolveFirst([staleUser]);

    // Ensure stale result did NOT overwrite "Feroze Basha"
    expect(screen.queryByText('Stale User')).not.toBeInTheDocument();
    expect(screen.getByText('Feroze Basha')).toBeInTheDocument();
  });

  it('selecting a candidate triggers onSelect callback to enable role/add-member workflow', async () => {
    searchTenantUserCandidatesMock.mockResolvedValue([ferozeCandidate]);
    const onSelect = vi.fn();

    render(<UserSearchCombobox tenantId={7} onSelect={onSelect} selectedUser={null} />);

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'feroze' } });

    const candidateButton = await screen.findByRole('button', { name: /Feroze Basha/i });
    fireEvent.click(candidateButton);

    expect(onSelect).toHaveBeenCalledWith(ferozeCandidate);
  });
});
