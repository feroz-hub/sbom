// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { SbomsTable } from '@/components/sboms/SbomsTable';
import type { LatestAnalysis, SBOMSource } from '@/types';

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

function sbomWithAnalysis(latestAnalysis: LatestAnalysis | null): SBOMSource {
  return {
    id: Number(latestAnalysis?.run_id ?? 100),
    sbom_name: `sbom-${latestAnalysis?.result ?? 'none'}`,
    sbom_type: 1,
    sbom_version: '1.0.0',
    projectid: null,
    project_id: null,
    project_name: null,
    created_by: 'tester',
    created_on: '2026-06-01T00:00:00Z',
    modified_by: null,
    modified_on: null,
    productver: null,
    status: 'validated',
    latest_analysis: latestAnalysis,
  };
}

describe('SbomsTable analysis column', () => {
  it('shows only SBOM Version in the Version column', () => {
    const withBoth = {
      ...sbomWithAnalysis(null),
      id: 201,
      sbom_name: 'with-both',
      sbom_version: '1.1.1',
      productver: '1.0.0',
      product_version: '1.0.0',
    };
    const productOnly = {
      ...sbomWithAnalysis(null),
      id: 202,
      sbom_name: 'product-only',
      sbom_version: null,
      productver: '1.0.0',
      product_version: '1.0.0',
    };

    render(wrap(<SbomsTable sboms={[withBoth, productOnly]} isLoading={false} error={null} />));

    const withBothRow = screen.getByText('with-both').closest('tr');
    const productOnlyRow = screen.getByText('product-only').closest('tr');
    expect(withBothRow?.children[5]).toHaveTextContent('1.1.1');
    expect(productOnlyRow?.children[5]).toHaveTextContent('—');
  });

  it('renders Not Run when no latest analysis exists', () => {
    render(wrap(<SbomsTable sboms={[sbomWithAnalysis(null)]} isLoading={false} error={null} />));

    const badge = screen.getByLabelText(/Analysis has not been run for this SBOM/i);
    expect(within(badge).getByText('Not Run')).toBeInTheDocument();
    expect(screen.queryByText('—')).not.toBeInTheDocument();
  });

  it.each([
    ['queued', 'queued', 'Queued'],
    ['running', 'running', 'Running'],
    ['completed', 'completed', 'Completed · 5 findings'],
    ['failed', 'failed', 'Failed'],
    ['interrupted', 'interrupted', 'Interrupted'],
  ])('renders %s latest analysis as %s', (result, status, label) => {
    render(
      wrap(
        <SbomsTable
          sboms={[
            sbomWithAnalysis({
              run_id: 77,
              status,
              result,
              finding_count: result === 'completed' ? 5 : 0,
              critical_count: result === 'completed' ? 1 : 0,
              high_count: result === 'completed' ? 2 : 0,
              medium_count: result === 'completed' ? 1 : 0,
              low_count: result === 'completed' ? 1 : 0,
              risk_score: result === 'completed' ? 12.5 : null,
              risk_level: result === 'completed' ? 'critical' : null,
              started_at: '2026-06-01T00:00:00Z',
              completed_at: result === 'running' ? null : '2026-06-01T00:05:00Z',
              error_message: result === 'failed' ? 'provider failed' : result === 'interrupted' ? 'worker restarted' : null,
            }),
          ]}
          isLoading={false}
          error={null}
        />,
      ),
    );

    const badge = screen.getByRole('link', { name: /SBOM 77:/i });
    expect(within(badge).getByText(label)).toBeInTheDocument();
    expect(badge).toHaveAttribute('href', '/analysis/77');
    if (result === 'completed') {
      expect(within(badge).getByText(/Critical 1/i)).toBeInTheDocument();
      expect(within(badge).getByText(/High 2/i)).toBeInTheDocument();
      expect(badge).toHaveClass('text-red-700');
      expect(badge).toHaveAttribute('title', expect.stringContaining('Critical: 1'));
      expect(badge).toHaveAttribute('title', expect.stringContaining('Risk level: critical'));
      expect(screen.queryByText(/^Completed 5$/)).not.toBeInTheDocument();
    }
    if (result === 'failed') {
      expect(screen.getByRole('link', { name: /provider failed/i })).toBeInTheDocument();
    }
    if (result === 'interrupted') {
      expect(screen.getByRole('link', { name: /worker restarted/i })).toBeInTheDocument();
    }
  });

  it('renders completed zero findings with an explanatory tooltip', () => {
    render(
      wrap(
        <SbomsTable
          sboms={[
            sbomWithAnalysis({
              run_id: 88,
              status: 'completed',
              result: 'pass',
              finding_count: 0,
              critical_count: 0,
              high_count: 0,
              medium_count: 0,
              low_count: 0,
              risk_score: 0,
              risk_level: 'none',
              started_at: '2026-06-01T00:00:00Z',
              completed_at: '2026-06-01T00:05:00Z',
              error_message: null,
            }),
          ]}
          isLoading={false}
          error={null}
        />,
      ),
    );

    const badge = screen.getByRole('link', { name: /SBOM 88:/i });
    expect(within(badge).getByText('Completed · 0 findings')).toBeInTheDocument();
    expect(badge).toHaveClass('text-green-700');
    expect(badge).toHaveAttribute('title', expect.stringContaining('No findings detected'));
  });

  it('uses theme-aware table row and action classes for dark mode', () => {
    render(
      wrap(
        <div className="dark">
          <SbomsTable
            sboms={[
              sbomWithAnalysis(null),
              {
                ...sbomWithAnalysis({
                  run_id: 101,
                  status: 'completed',
                  result: 'pass',
                  finding_count: 0,
                }),
                id: 101,
              },
            ]}
            isLoading={false}
            error={null}
          />
        </div>,
      ),
    );

    const table = screen.getByRole('table', { name: /SBOM inventory table/i });
    expect(table).toHaveClass('bg-surface');
    expect(table).toHaveClass('[&_tbody_tr:nth-child(odd)]:bg-surface');
    expect(table).toHaveClass('[&_tbody_tr:nth-child(even)]:bg-row-alt');
    expect(table).toHaveClass('[&_tbody_tr]:hover:bg-row-hover');

    const row = screen.getByText('#100').closest('tr');
    expect(row?.className).not.toMatch(/bg-(white|slate-50|gray-50|blue-50)/);
    expect(row?.className).not.toContain('hover:bg-hcl-light/40');

    const viewButton = screen.getAllByRole('button', { name: /View SBOM/i })[0];
    expect(viewButton).toHaveClass('text-hcl-muted');
    expect(viewButton).toHaveClass('hover:bg-row-hover');
  });
});
