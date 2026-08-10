// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { RunsTable } from '@/components/analysis/RunsTable';
import type { AnalysisRun } from '@/types';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }),
}));

vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast: vi.fn() }),
}));

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function run(overrides: Partial<AnalysisRun>): AnalysisRun {
  return {
    id: 1,
    sbom_id: 10,
    sbom_name: 'clean-backfill',
    project_id: null,
    run_status: 'PASS',
    source: 'BACKFILL',
    total_components: 1,
    components_with_cpe: 0,
    total_findings: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    unknown_count: 0,
    query_error_count: 0,
    duration_ms: 1,
    started_on: '2026-07-02T00:00:00Z',
    completed_on: '2026-07-02T00:00:01Z',
    error_message: null,
    ...overrides,
  };
}

describe('RunsTable status classification', () => {
  it('renders legacy PASS backfill rows as No issues and keeps them under the OK filter', () => {
    render(
      wrap(
        <RunsTable
          runs={[
            run({ id: 2, run_status: 'PASS', total_findings: 0, source: 'BACKFILL' }),
            run({ id: 1, sbom_name: 'vulnerable', run_status: 'FINDINGS', total_findings: 35 }),
          ]}
          isLoading={false}
          error={null}
        />,
      ),
    );

    const backfillRow = screen.getByText('#2').closest('tr');
    expect(backfillRow).not.toBeNull();
    expect(within(backfillRow as HTMLElement).getByText('No issues')).toBeInTheDocument();
    expect(within(backfillRow as HTMLElement).getByText('None')).toBeInTheDocument();
    expect(within(backfillRow as HTMLElement).getByText('BACKFILL')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'OK' } });

    expect(screen.getByText('#2')).toBeInTheDocument();
    expect(screen.queryByText('#1')).not.toBeInTheDocument();
  });
});
