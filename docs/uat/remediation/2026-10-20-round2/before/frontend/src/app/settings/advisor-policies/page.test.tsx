// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  render,
  screen,
  waitFor,
  cleanup,
  within,
  act,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { ApiError } from '@/lib/api';
const api = vi.hoisted(() => ({
  getAdvisorPolicy: vi.fn(),
  getAdvisorPolicyHistory: vi.fn(),
  publishAdvisorPolicy: vi.fn(),
}));
let tenantId: number | null = 1;
let loading = false;
let queryClient: QueryClient;
let canRead = true;
let platformRead = true;
let canUpdate = true;
vi.mock('@/lib/advisorPolicyApi', () => api);
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { userId: 1, permissions: [] },
    activeTenantId: tenantId,
    activeTenant: { name: `Tenant ${tenantId}` },
    hasPermission: (p: string) =>
      p.startsWith('platform:') && !platformRead
        ? false
        : p.endsWith(':read')
          ? canRead
          : canUpdate,
    isLoading: loading,
  }),
}));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: () => null }));
import Page from './page';
import PlatformPage from '../../platform/configuration/advisor-policies/page';
const state = {
  configured: false,
  effective: null,
  tenant_override: null,
  platform_default: null,
  row_version: 0,
};
function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}
afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  loading = false;
  tenantId = 1;
  canRead = true;
  platformRead = true;
  canUpdate = true;
  api.getAdvisorPolicy.mockResolvedValue(state);
  api.getAdvisorPolicyHistory.mockResolvedValue({ items: [] });
  api.publishAdvisorPolicy.mockResolvedValue({ ...state, row_version: 1 });
});
async function publish(user: ReturnType<typeof userEvent.setup>) {
  await user.click(
    screen.getByRole('button', { name: 'Publish policy version' }),
  );
  await user.click(
    await screen.findByRole('button', { name: 'Confirm publication' }),
  );
}
async function fill() {
  const user = userEvent.setup();
  await screen.findByLabelText('Accepted risk policy mode');
  await user.selectOptions(
    screen.getByLabelText('Accepted risk policy mode'),
    'ACTIVE',
  );
  await user.type(
    screen.getByLabelText('Accepted risk reason'),
    'Approved risk threshold',
  );
  return user;
}
describe('Tenant advisor policies', () => {
  it('publishes platform defaults without tenant context or inheritance mode', async () => {
    tenantId = null;
    render(<PlatformPage />, { wrapper });
    const user = await fill();
    expect(
      screen.queryByRole('option', { name: 'Inherit platform default' }),
    ).not.toBeInTheDocument();
    await publish(user);
    await waitFor(() =>
      expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
        null,
        'accepted-risk',
        expect.objectContaining({ status: 'ACTIVE' }),
      ),
    );
  });
  it('denies platform configuration to a tenant administrator', () => {
    platformRead = false;
    render(<PlatformPage />, { wrapper });
    expect(screen.getByRole('alert')).toHaveTextContent('not permitted');
    expect(api.getAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('publishes a version scoped to the active tenant with concurrency token', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await publish(user);
    await waitFor(() =>
      expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
        1,
        'accepted-risk',
        expect.objectContaining({
          status: 'ACTIVE',
          row_version: 0,
          reason: 'Approved risk threshold',
          rules: expect.objectContaining({ max_actionable_severity: 'MEDIUM' }),
        }),
      ),
    );
    expect(
      await screen.findByText('Policy version published.'),
    ).toBeInTheDocument();
  });
  it.each(['INHERIT', 'DISABLED'])(
    'publishes %s without active rules',
    async (status) => {
      render(<Page />, { wrapper });
      const user = userEvent.setup();
      await screen.findByLabelText('Accepted risk policy mode');
      await user.selectOptions(
        screen.getByLabelText('Accepted risk policy mode'),
        status,
      );
      await user.type(
        screen.getByLabelText('Accepted risk reason'),
        'Change tenant mode',
      );
      await publish(user);
      await waitFor(() =>
        expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
          1,
          'accepted-risk',
          { status, rules: null, reason: 'Change tenant mode', row_version: 0 },
        ),
      );
    },
  );
  it('rejects malformed JSON before a write', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.click(screen.getByText('Advanced JSON'));
    await user.clear(screen.getByLabelText('Accepted risk rules'));
    await user.type(screen.getByLabelText('Accepted risk rules'), 'invalid');
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('allows analysts to read without publishing', async () => {
    canUpdate = false;
    render(<Page />, { wrapper });
    await screen.findByLabelText('Accepted risk policy mode');
    expect(screen.getByLabelText('Accepted risk policy mode')).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Publish policy version' }),
    ).not.toBeInTheDocument();
  });
  it('does not fetch without read permission', () => {
    canRead = false;
    render(<Page />, { wrapper });
    expect(screen.getByRole('alert')).toHaveTextContent('not permitted');
    expect(api.getAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('blocks stale writes until the latest policy is reloaded', async () => {
    api.publishAdvisorPolicy.mockRejectedValue(new ApiError('Conflict', 409));
    render(<Page />, { wrapper });
    const user = await fill();
    await publish(user);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Another administrator',
    );
    expect(screen.getByLabelText('Accepted risk policy mode')).toBeDisabled();
    api.getAdvisorPolicy.mockResolvedValue({ ...state, row_version: 2 });
    await user.click(screen.getByRole('button', { name: /Reload latest/ }));
    await waitFor(() =>
      expect(
        screen.getByLabelText('Accepted risk policy mode'),
      ).not.toBeDisabled(),
    );
  });
  it('discards the prior tenant draft on a tenant switch', async () => {
    const rendered = render(<Page />, { wrapper });
    await fill();
    tenantId = 2;
    rendered.rerender(<Page />);
    await waitFor(() =>
      expect(api.getAdvisorPolicy).toHaveBeenCalledWith(2, 'accepted-risk'),
    );
    expect(await screen.findByLabelText('Accepted risk reason')).toHaveValue(
      '',
    );
  });
});

describe('Policy console interactions', () => {
  it('navigates all tabs by keyboard and retains each local draft', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    const first = screen.getByRole('tab', { name: 'Accepted Risk' });
    first.focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Trust' })).toHaveFocus();
    await user.selectOptions(
      await screen.findByLabelText('Trust policy mode'),
      'ACTIVE',
    );
    await user.type(screen.getByLabelText('Trust reason'), 'Trust review');
    await user.keyboard('{End}');
    await user.click(
      screen.getByRole('tab', { name: 'Recommendation Scoring' }),
    );
    expect(
      screen.getByText(/positive total and are normalized/),
    ).toBeInTheDocument();
    await user.click(first);
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue(
      'Approved risk threshold',
    );
    await user.click(screen.getByRole('tab', { name: 'Trust' }));
    expect(screen.getByLabelText('Trust reason')).toHaveValue('Trust review');
  });
  it('serializes the visual form, nulls, exact lifecycle values and a zero vulnerability limit', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.selectOptions(
      screen.getByLabelText('Maximum actionable severity'),
      'LOW',
    );
    await user.clear(screen.getByLabelText('Maximum CVSS score'));
    await user.clear(screen.getByLabelText('Maximum analysis age (days)'));
    await user.clear(
      screen.getByLabelText('Maximum actionable vulnerabilities'),
    );
    await user.type(
      screen.getByLabelText('Maximum actionable vulnerabilities'),
      '0',
    );
    await user.click(screen.getByLabelText('SUPPORTED'));
    await user.click(screen.getByLabelText('EOS'));
    await user.click(screen.getByLabelText('UNDER_INVESTIGATION'));
    await publish(user);
    expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
      1,
      'accepted-risk',
      expect.objectContaining({
        rules: {
          max_actionable_severity: 'LOW',
          max_cvss_score: null,
          max_actionable_vulnerabilities: 0,
          max_analysis_age_days: null,
          allowed_lifecycle: ['SUPPORTED', 'EOS'],
          allowed_actionable_vex_statuses: ['AFFECTED'],
        },
      }),
    );
  });
  it.each([
    ['Maximum CVSS score', '-1'],
    ['Maximum CVSS score', '10.1'],
    ['Maximum CVSS score', 'abc'],
    ['Maximum actionable vulnerabilities', '-1'],
    ['Maximum actionable vulnerabilities', '1.5'],
    ['Maximum analysis age (days)', '0'],
    ['Maximum analysis age (days)', '1.5'],
  ])('blocks invalid %s value %s before confirmation', async (label, value) => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.clear(screen.getByLabelText(label));
    await user.type(screen.getByLabelText(label), value);
    expect(screen.getByLabelText(label)).toHaveAttribute(
      'aria-invalid',
      'true',
    );
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('requires an actionable VEX status', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.click(screen.getByLabelText('AFFECTED'));
    await user.click(screen.getByLabelText('UNDER_INVESTIGATION'));
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect(
      screen.getAllByText(/allowed_actionable_vex_statuses must be/).length,
    ).toBeGreaterThan(0);
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('synchronizes JSON and form without dropping fields and blocks HIGH severity', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.click(screen.getByText('Advanced JSON'));
    const json = screen.getByLabelText('Accepted risk rules');
    await user.clear(json);
    await user.paste(
      JSON.stringify({
        max_actionable_severity: 'HIGH',
        max_cvss_score: 4.2,
        allowed_lifecycle: ['MAINTENANCE'],
        custom_field: 'keep me',
      }),
    );
    expect(screen.getByLabelText('Maximum CVSS score')).toHaveValue('4.2');
    expect(
      screen.getByLabelText('Maximum actionable severity'),
    ).toHaveAttribute('aria-invalid', 'true');
    await user.selectOptions(
      screen.getByLabelText('Maximum actionable severity'),
      'LOW',
    );
    expect(JSON.parse((json as HTMLTextAreaElement).value)).toEqual(
      expect.objectContaining({
        max_actionable_severity: 'LOW',
        max_cvss_score: 4.2,
        custom_field: 'keep me',
      }),
    );
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
  });
  it('preserves malformed JSON until repaired, then resumes the form', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.click(screen.getByText('Advanced JSON'));
    const json = screen.getByLabelText('Accepted risk rules');
    await user.clear(json);
    await user.paste('{invalid');
    expect(json).toHaveValue('{invalid');
    expect(
      screen.queryByLabelText('Maximum CVSS score'),
    ).not.toBeInTheDocument();
    await user.clear(json);
    await user.paste(
      JSON.stringify({ max_actionable_severity: 'LOW', max_cvss_score: null }),
    );
    expect(screen.getByLabelText('Maximum CVSS score')).toHaveValue('');
    await user.type(screen.getByLabelText('Maximum CVSS score'), '6.9');
    expect(JSON.parse((json as HTMLTextAreaElement).value).max_cvss_score).toBe(
      6.9,
    );
  });
  it('requires a non-whitespace reason before review', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.clear(screen.getByLabelText('Accepted risk reason'));
    await user.type(screen.getByLabelText('Accepted risk reason'), '   ');
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect(
      screen.getByText('Enter a reason for this change.'),
    ).toBeInTheDocument();
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Accepted risk reason')).toHaveAttribute(
      'maxlength',
      '2000',
    );
  });
  it('reviews the proposed change and cancels without losing edits', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('INHERIT → ACTIVE');
    expect(dialog).toHaveTextContent('Approved risk threshold');
    expect(api.publishAdvisorPolicy).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue(
      'Approved risk threshold',
    );
  });
  it('keeps the draft and original concurrency token during background refetches', async () => {
    render(<Page />, { wrapper });
    const user = await fill();
    await act(async () => {
      queryClient.setQueryData(['advisor-policy', 1, 'accepted-risk'], {
        ...state,
        row_version: 9,
      });
    });
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue(
      'Approved risk threshold',
    );
    expect(
      await screen.findByText(/newer published policy is available/),
    ).toBeInTheDocument();
    await publish(user);
    expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
      1,
      'accepted-risk',
      expect.objectContaining({ row_version: 0 }),
    );
  });
  it('keeps conflicts blocked if reloading fails and clears them only after an explicit successful reload', async () => {
    api.publishAdvisorPolicy.mockRejectedValue(new ApiError('Conflict', 409));
    render(<Page />, { wrapper });
    const user = await fill();
    await publish(user);
    await screen.findByText(/Another administrator/);
    api.getAdvisorPolicy.mockRejectedValue(new Error('Offline'));
    await user.click(screen.getByRole('button', { name: /Reload latest/ }));
    await waitFor(() =>
      expect(screen.getByLabelText('Accepted risk policy mode')).toBeDisabled(),
    );
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue(
      'Approved risk threshold',
    );
    api.getAdvisorPolicy.mockResolvedValue({ ...state, row_version: 3 });
    await user.click(screen.getByRole('button', { name: /Reload latest/ }));
    await waitFor(() =>
      expect(
        screen.getByLabelText('Accepted risk policy mode'),
      ).not.toBeDisabled(),
    );
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue('');
  });
  it.each(['resolve', 'reject'])(
    'ignores a late publication %s after a tenant switch',
    async (outcome) => {
      let resolve!: (value: unknown) => void;
      let reject!: (reason: Error) => void;
      api.publishAdvisorPolicy.mockReturnValue(
        new Promise((yes, no) => {
          resolve = yes;
          reject = no;
        }),
      );
      const rendered = render(<Page />, { wrapper });
      const user = await fill();
      await publish(user);
      await waitFor(() => expect(api.publishAdvisorPolicy).toHaveBeenCalled());
      tenantId = 2;
      rendered.rerender(<Page />);
      await screen.findByLabelText('Accepted risk reason');
      await act(async () => {
        if (outcome === 'resolve') resolve({ ...state, row_version: 99 });
        else reject(new ApiError('Old tenant conflict', 409));
      });
      expect(screen.getByLabelText('Accepted risk reason')).toHaveValue('');
      expect(
        screen.queryByText('Policy version published.'),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByText(/Another administrator/),
      ).not.toBeInTheDocument();
      expect(
        queryClient.getQueryData(['advisor-policy', 2, 'accepted-risk']),
      ).toEqual(state);
    },
  );
  it('shows loading and policy-load errors with retry', async () => {
    api.getAdvisorPolicy.mockReturnValue(new Promise(() => {}));
    const rendered = render(<Page />, { wrapper });
    expect(screen.getByRole('status')).toHaveTextContent('Loading policy');
    rendered.unmount();
    queryClient.clear();
    api.getAdvisorPolicy.mockRejectedValue(new Error('Unavailable'));
    render(<Page />, { wrapper });
    expect(await screen.findByRole('alert')).toHaveTextContent('Unavailable');
    api.getAdvisorPolicy.mockResolvedValue(state);
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(
      await screen.findByLabelText('Accepted risk policy mode'),
    ).toBeInTheDocument();
  });
  it('renders empty and populated read-only version history', async () => {
    canUpdate = false;
    render(<Page />, { wrapper });
    await screen.findByLabelText('Accepted risk policy mode');
    await userEvent.click(screen.getAllByText('Version history')[0]);
    expect(screen.getAllByText('No versions published.')[0]).toBeVisible();
    await act(async () => {
      queryClient.setQueryData(['advisor-policy-history', 1, 'accepted-risk'], {
        items: [
          {
            id: 4,
            version: 2,
            status: 'ACTIVE',
            scope: 'TENANT',
            rules: { max_actionable_severity: 'LOW' },
            created_at: '2026-10-16T00:00:00Z',
            created_by: 'admin@example.test',
            reason: 'Reviewed threshold',
          },
        ],
      });
    });
    expect(await screen.findByText('Version 2')).toBeVisible();
    expect(screen.getByText('admin@example.test')).toBeVisible();
    expect(screen.getByText('Reviewed threshold')).toBeVisible();
    await userEvent.click(screen.getByText('Rules for version 2'));
    expect(screen.getByText(/"max_actionable_severity": "LOW"/)).toBeVisible();
  });
  it('shows history load failures and retries them', async () => {
    api.getAdvisorPolicyHistory.mockRejectedValue(new Error('Offline'));
    render(<Page />, { wrapper });
    await screen.findByLabelText('Accepted risk policy mode');
    await userEvent.click(screen.getAllByText('Version history')[0]);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Unable to load history',
    );
    api.getAdvisorPolicyHistory.mockResolvedValue({ items: [] });
    await userEvent.click(
      screen.getByRole('button', { name: 'Retry history' }),
    );
    expect(await screen.findByText('No versions published.')).toBeVisible();
  });
  it('does not fetch while access is loading or tenant context is absent', () => {
    loading = true;
    const rendered = render(<Page />, { wrapper });
    expect(screen.getByRole('status')).toHaveTextContent('Verifying');
    expect(api.getAdvisorPolicy).not.toHaveBeenCalled();
    loading = false;
    tenantId = null;
    rendered.rerender(<Page />);
    expect(screen.getByRole('alert')).toHaveTextContent('not permitted');
    expect(api.getAdvisorPolicy).not.toHaveBeenCalled();
  });
});

describe('Trust and scoring publication', () => {
  it.each([
    ['Trust', 'Trust', 'trust'],
    ['Recommendation Scoring', 'Recommendation scoring', 'scoring'],
  ])(
    'publishes valid %s rules through the existing API',
    async (tab, label, kind) => {
      render(<Page />, { wrapper });
      const user = userEvent.setup();
      await user.click(screen.getByRole('tab', { name: tab }));
      await user.selectOptions(
        await screen.findByLabelText(`${label} policy mode`),
        'ACTIVE',
      );
      await user.type(
        screen.getByLabelText(`${label} reason`),
        'Reviewed policy',
      );
      await publish(user);
      expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(
        1,
        kind,
        expect.objectContaining({
          status: 'ACTIVE',
          row_version: 0,
          reason: 'Reviewed policy',
          rules: expect.any(Object),
        }),
      );
    },
  );
  it('preserves form values after a non-conflict publication failure', async () => {
    api.publishAdvisorPolicy.mockRejectedValue(
      new Error('Unable to reach service'),
    );
    render(<Page />, { wrapper });
    const user = await fill();
    await publish(user);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Unable to reach service',
    );
    expect(screen.getByLabelText('Accepted risk reason')).toHaveValue(
      'Approved risk threshold',
    );
    expect(screen.getByLabelText('Maximum CVSS score')).toHaveValue('6.9');
    expect(
      screen.getByLabelText('Accepted risk policy mode'),
    ).not.toBeDisabled();
  });
  it('invalidates the existing history and advisor surfaces after publishing', async () => {
    const historyRead = api.getAdvisorPolicyHistory.mock.calls.length;
    render(<Page />, { wrapper });
    const user = await fill();
    await publish(user);
    await screen.findByText('Policy version published.');
    expect(api.getAdvisorPolicyHistory.mock.calls.length).toBeGreaterThan(
      historyRead + 3,
    );
  });
  it('passes axe checks on each selected policy and the publication dialog', async () => {
    // AppShell supplies the page landmark in production.
    const { container } = render(
      <main>
        <Page />
      </main>,
      { wrapper },
    );
    const user = await fill();
    expect((await axe(container)).violations).toEqual([]);
    await user.click(
      screen.getByRole('button', { name: 'Publish policy version' }),
    );
    expect((await axe(document.body)).violations).toEqual([]);
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Cancel',
      }),
    );
    for (const name of ['Trust', 'Recommendation Scoring']) {
      await user.click(screen.getByRole('tab', { name }));
      expect((await axe(container)).violations).toEqual([]);
    }
  });
});

describe('Published policy metadata', () => {
  it('distinguishes an inherited platform version from the tenant mode', async () => {
    const version = {
      id: 5,
      version: 4,
      status: 'ACTIVE',
      scope: 'PLATFORM',
      rules: { max_actionable_severity: 'LOW' },
      created_at: null,
    };
    api.getAdvisorPolicy.mockResolvedValue({
      ...state,
      configured: true,
      effective: version,
      platform_default: version,
    });
    render(<Page />, { wrapper });
    const summary = await screen.findByRole('region', {
      name: 'Accepted Risk published configuration',
    });
    expect(summary).toHaveTextContent('Platform default');
    expect(summary).toHaveTextContent('v4');
    expect(summary).toHaveTextContent('INHERIT');
    expect(
      screen.queryByRole('option', { name: 'Use platform default' }),
    ).not.toBeInTheDocument();
  });
  it('shows the disabled tenant mode without implying the platform policy applies', async () => {
    api.getAdvisorPolicy.mockResolvedValue({
      ...state,
      tenant_override: {
        id: 3,
        version: 2,
        status: 'DISABLED',
        scope: 'TENANT',
        rules: {},
        created_at: null,
      },
    });
    render(<Page />, { wrapper });
    const summary = await screen.findByRole('region', {
      name: 'Accepted Risk published configuration',
    });
    expect(summary).toHaveTextContent('No effective policy');
    expect(summary).toHaveTextContent('DISABLED · v2');
    expect(screen.getByLabelText('Accepted risk policy mode')).toHaveValue(
      'DISABLED',
    );
  });
});
