// @vitest-environment jsdom

import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { UserSearchCombobox } from './UserSearchCombobox';
import * as api from '@/lib/api';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual('@/lib/api');
  return {
    ...actual,
    searchPlatformUsers: vi.fn(),
    searchTenantUserCandidates: vi.fn(),
  };
});

describe('UserSearchCombobox', () => {
  it('renders input placeholder', () => {
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    expect(screen.getByPlaceholderText(/Search existing SBOM users/i)).toBeInTheDocument();
  });

  it('searches platform users when no tenantId provided', async () => {
    vi.mocked(api.searchPlatformUsers).mockResolvedValue([
      {
        id: 1,
        email: 'test@example.com',
        display_name: 'Test User',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
      },
    ]);

    const onSelect = vi.fn();
    render(<UserSearchCombobox onSelect={onSelect} selectedUser={null} />);

    const input = screen.getByPlaceholderText(/Search existing SBOM users/i);
    fireEvent.change(input, { target: { value: 'Test' } });

    await waitFor(() => {
      expect(api.searchPlatformUsers).toHaveBeenCalledWith('Test');
      expect(screen.getByText('Test User')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Test User'));
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'test@example.com' })
    );
  });
});
