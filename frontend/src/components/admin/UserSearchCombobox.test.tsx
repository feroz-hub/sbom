// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { isEligibleAdministrator, UserSearchCombobox } from './UserSearchCombobox';
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
  it('keeps results in layout flow and supports keyboard selection without submitting the dialog', async () => {
    const candidate = { id: '00000000-0000-4000-8000-00000000001f', email: 'keyboard@example.test', display_name: 'Keyboard Candidate', status: 'ACTIVE', email_verified: true, verification_required: false };
    vi.mocked(api.searchTenantUserCandidates).mockResolvedValue([candidate]);
    const select = vi.fn();
    render(<UserSearchCombobox tenantId="cd9e3737-67fe-4d06-8e6c-8d185854e11b" onSelect={select} selectedUser={null} />);
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'keyboard' } });
    const option = await screen.findByRole('option');
    expect(screen.getByRole('listbox')).not.toHaveClass('absolute');
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(input).toHaveAttribute('aria-activedescendant', option.id);
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(select).toHaveBeenCalledExactlyOnceWith(candidate);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('Escape dismisses results, keeps input focus and does not dismiss the parent dialog', async () => {
    vi.mocked(api.searchTenantUserCandidates).mockResolvedValue([]);
    const bubble = vi.fn();
    render(<div onKeyDown={bubble}><UserSearchCombobox tenantId={1} onSelect={vi.fn()} selectedUser={null} /></div>);
    const input = screen.getByRole('combobox');
    input.focus();
    fireEvent.change(input, { target: { value: 'missing' } });
    await screen.findByRole('listbox');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(input).toHaveFocus();
    expect(bubble).not.toHaveBeenCalled();
  });

  it('keeps the popup in place until an outside pointer click completes', async () => {
    vi.mocked(api.searchTenantUserCandidates).mockResolvedValue([]);
    const cancel = vi.fn();
    render(<><UserSearchCombobox tenantId={1} onSelect={vi.fn()} selectedUser={null} /><button onClick={cancel}>Cancel</button></>);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'missing' } });
    await screen.findByRole('listbox');
    const button = screen.getByRole('button', { name: 'Cancel' });
    fireEvent.mouseDown(button);
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.click(button);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });
  it('does not search tenant candidates before two trimmed characters', async () => {
    render(<UserSearchCombobox tenantId={1} onSelect={() => {}} selectedUser={null} />);
    fireEvent.change(screen.getByRole('combobox', { name: 'Search existing user' }), { target: { value: ' a ' } });
    await new Promise(resolve => setTimeout(resolve, 300));
    expect(api.searchTenantUserCandidates).not.toHaveBeenCalled();
    expect(api.searchPlatformUsers).not.toHaveBeenCalled();
  });
  it('does not expose technical IDs or subjects in the tenant workflow', () => {
    render(<UserSearchCombobox tenantId={1} onSelect={() => {}} selectedUser={{ id: '00000000-0000-4000-8000-0000000f1206', display_name: 'Human Name', email: 'human@example.test', status: 'ACTIVE', email_verified: true, verification_required: false, external_subject: 'private-subject', external_issuer: 'private-issuer' }} />);
    expect(screen.getByText('Human Name')).toBeInTheDocument();
    expect(screen.getByText('human@example.test')).toBeInTheDocument();
    expect(screen.queryByText('Show technical details')).not.toBeInTheDocument();
    expect(screen.queryByText(/987654|private-subject|private-issuer/)).not.toBeInTheDocument();
  });
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
        id: '00000000-0000-4000-8000-000000000003',
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
      expect.objectContaining({ id: '00000000-0000-4000-8000-000000000003', email: 'ferozebasha.s@hcltech.com' })
    );
  });

  it('displays Feroze for an exact email search', async () => {
    vi.mocked(api.searchPlatformUsers).mockResolvedValue([
      {
        id: '00000000-0000-4000-8000-000000000003',
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
        id: '00000000-0000-4000-8000-000000000003',
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
      expect.objectContaining({ id: '00000000-0000-4000-8000-000000000003', display_name: 'Feroze Basha' }),
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
        id: '00000000-0000-4000-8000-000000000002',
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
    const option = await screen.findByRole('option', { name: /Disabled User/ });
    expect(option).toBeDisabled();
    fireEvent.click(option);
    expect(onSelect).not.toHaveBeenCalled();
    expect(option).toHaveTextContent('@disabled');
    expect(option).toHaveTextContent('Verification required');
  });
});

it('allows an approved directory identity without claiming mailbox verification', () => {
  const candidate = { id: '00000000-0000-4000-8000-00000000007b', email: 'directory@example.test', display_name: 'Directory member', status: 'ACTIVE', email_verified: false, verification_required: false, providers: ['MICROSOFT_ENTRA'] };
  expect(isEligibleAdministrator(candidate)).toBe(true);
  expect(isEligibleAdministrator({ ...candidate, status: 'PENDING' })).toBe(false);
  expect(isEligibleAdministrator({ ...candidate, providers: ['HCL_CS'] })).toBe(false);
});

it('refreshes candidate eligibility after a local mutation revision without clearing search text', async () => {
  const candidate = { id: '00000000-0000-4000-8000-000000000037', display_name: 'New member', email: 'member@example.test', status: 'ACTIVE', email_verified: true, verification_required: false };
  vi.mocked(api.searchTenantUserCandidates).mockResolvedValue([candidate]);
  const view = render(<UserSearchCombobox tenantId={7} revision={0} onSelect={() => {}} selectedUser={null} />);
  const input = screen.getByRole('combobox', { name: 'Search existing user' });
  fireEvent.change(input, { target: { value: 'member' } });
  await screen.findByText('New member');
  vi.mocked(api.searchTenantUserCandidates).mockResolvedValue([]);
  view.rerender(<UserSearchCombobox tenantId={7} revision={1} onSelect={() => {}} selectedUser={null} />);
  await waitFor(() => expect(screen.queryByText('New member')).not.toBeInTheDocument());
  expect(input).toHaveValue('member');
  await waitFor(() => expect(api.searchTenantUserCandidates).toHaveBeenCalledTimes(2));
});
