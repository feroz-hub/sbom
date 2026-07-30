// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders input placeholder', () => {
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    expect(screen.getByPlaceholderText(/Search existing SBOM users/i)).toBeInTheDocument();
  });

  it('uses global platform search and renders a partial display-name match', async () => {
    vi.mocked(api.searchPlatformUsers).mockResolvedValue([
      {
        id: 3,
        email: 'ferozebasha.s@hcltech.com',
        display_name: 'Feroze Basha',
        username: 'ferozebasha',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
      },
    ]);

    const onSelect = vi.fn();
    render(<UserSearchCombobox onSelect={onSelect} selectedUser={null} />);

    const input = screen.getByPlaceholderText(/Search existing SBOM users/i);
    fireEvent.change(input, { target: { value: 'Feroze' } });

    await waitFor(() => {
      expect(api.searchPlatformUsers).toHaveBeenCalledWith('Feroze');
      expect(api.searchTenantUserCandidates).not.toHaveBeenCalled();
      expect(screen.getByText('Feroze Basha')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Feroze Basha'));
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({ id: 3, email: 'ferozebasha.s@hcltech.com' })
    );
  });

  it('displays Feroze for an exact email search', async () => {
    vi.mocked(api.searchPlatformUsers).mockResolvedValue([
      {
        id: 3,
        email: 'ferozebasha.s@hcltech.com',
        display_name: 'Feroze Basha',
        username: 'ferozebasha',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
      },
    ]);
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    fireEvent.change(screen.getByPlaceholderText(/Search existing SBOM users/i), {
      target: { value: 'ferozebasha.s@hcltech.com' },
    });
    await waitFor(() => {
      expect(api.searchPlatformUsers).toHaveBeenCalledWith('ferozebasha.s@hcltech.com');
      expect(screen.getByText('Feroze Basha')).toBeInTheDocument();
      expect(screen.getByText('ferozebasha.s@hcltech.com')).toBeInTheDocument();
      expect(screen.getByText('@ferozebasha')).toBeInTheDocument();
    });
  });

  it('does not request or show no-results messaging for an empty query', async () => {
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    const input = screen.getByPlaceholderText(/Search existing SBOM users/i);

    fireEvent.change(input, { target: { value: '   ' } });

    await waitFor(() => expect(api.searchPlatformUsers).not.toHaveBeenCalled());
    expect(screen.queryByText(/No matching existing SBOM users found/)).not.toBeInTheDocument();
  });

  it('builds the global platform endpoint and unwraps its items response', async () => {
    const realApi = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [{
        id: 3,
        email: 'ferozebasha.s@hcltech.com',
        display_name: 'Feroze Basha',
        username: 'ferozebasha',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
      }],
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    const items = await realApi.searchPlatformUsers('Feroze Basha');

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toMatch(/\/api\/platform\/users\/search\?q=Feroze\+Basha$/);
    expect(options.method ?? 'GET').toBe('GET');
    expect(items).toEqual([
      expect.objectContaining({ id: 3, display_name: 'Feroze Basha' }),
    ]);
  });

  it('shows a loading state and no-results state', async () => {
    let resolveSearch: (value: api.UserSearchResult[]) => void = () => {};
    vi.mocked(api.searchPlatformUsers).mockImplementation(
      () => new Promise((resolve) => { resolveSearch = resolve; }),
    );
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    fireEvent.change(screen.getByPlaceholderText(/Search existing SBOM users/i), {
      target: { value: 'nobody' },
    });
    expect(await screen.findByRole('status')).toHaveTextContent('User search loading');
    resolveSearch([]);
    expect(await screen.findByText(/No matching existing SBOM users found/)).toBeInTheDocument();
  });

  it('shows a safe search error', async () => {
    vi.mocked(api.searchPlatformUsers).mockRejectedValue(new Error('network'));
    render(<UserSearchCombobox onSelect={() => {}} selectedUser={null} />);
    fireEvent.change(screen.getByPlaceholderText(/Search existing SBOM users/i), {
      target: { value: 'failed' },
    });
    expect(await screen.findByRole('alert')).toHaveTextContent('User search could not be completed');
  });

  it('prevents selecting an inactive or unverified initial administrator', async () => {
    vi.mocked(api.searchPlatformUsers).mockResolvedValue([
      {
        id: 2,
        email: 'disabled@example.test',
        display_name: 'Disabled User',
        username: 'disabled',
        status: 'DISABLED',
        email_verified: false,
        verification_required: true,
      },
    ]);
    const onSelect = vi.fn();
    render(
      <UserSearchCombobox
        onSelect={onSelect}
        selectedUser={null}
        requireEligible
      />,
    );
    fireEvent.change(screen.getByPlaceholderText(/Search existing SBOM users/i), {
      target: { value: 'Disabled User' },
    });
    const option = await screen.findByRole('button', { name: /Disabled User/ });
    expect(option).toBeDisabled();
    fireEvent.click(option);
    expect(onSelect).not.toHaveBeenCalled();
    expect(option).toHaveTextContent('@disabled');
    expect(option).toHaveTextContent('Verification required');
  });
});
