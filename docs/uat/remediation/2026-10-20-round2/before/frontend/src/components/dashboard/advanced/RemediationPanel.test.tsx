// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RemediationPanel } from './RemediationPanel';
import { getDashboardRemediation, getDashboardRemediationStats } from '@/lib/api';

vi.mock('@/lib/api', () => ({
  getDashboardRemediation: vi.fn(),
  getDashboardRemediationStats: vi.fn(),
}));

const remediationSummary = {
  schema_version: 1,
  generated_at: '2026-06-11T00:00:00Z',
  mttr_days: { critical: 5, high: 12, medium: null, low: null, unknown: null },
  resolved_total: 4,
  reopened_total: 0,
  velocity: {
    window_days: 30,
    new_findings: 8,
    resolved_findings: 4,
    net: 4,
  },
  sla: {
    overdue: 2,
    due_soon: 1,
    ok: 7,
    budgets_days: { critical: 7, high: 30, medium: 90, low: 180, unknown: 180 },
    by_severity_overdue: { critical: 2 },
    worst_offenders: [],
  },
};

function renderPanel() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RemediationPanel />
    </QueryClientProvider>,
  );
}

describe('RemediationPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders remediation status, SLA, and aging stats', async () => {
    vi.mocked(getDashboardRemediation).mockResolvedValue(remediationSummary);
    vi.mocked(getDashboardRemediationStats).mockResolvedValue({
      status_counts: { open: 12, in_progress: 3, fixed: 4, accepted_risk: 1, closed: 0 },
      aging_count: 2,
      sla: { overdue: 2, due_soon: 1, ok: 7 },
    });

    renderPanel();

    expect(await screen.findByText('Open')).toBeInTheDocument();
    expect(screen.getByText('In progress')).toBeInTheDocument();
    expect(screen.getByText('Fixed')).toBeInTheDocument();
    expect(screen.getByText('Accepted risk')).toBeInTheDocument();
    expect(screen.getByText('Aging 30d')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });

  it('shows retry action when remediation dashboard data fails to load', async () => {
    vi.mocked(getDashboardRemediation).mockRejectedValue(new Error('network'));
    vi.mocked(getDashboardRemediationStats).mockRejectedValue(new Error('network'));

    renderPanel();

    expect(await screen.findByText('Remediation metrics unavailable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });
});
