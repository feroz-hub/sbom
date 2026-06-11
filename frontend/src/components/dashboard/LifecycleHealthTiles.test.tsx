// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const getDashboardLifecycle = vi.fn();
const getDashboardHealth = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getDashboardLifecycle: (...args: unknown[]) => getDashboardLifecycle(...args),
    getDashboardHealth: (...args: unknown[]) => getDashboardHealth(...args),
  };
});

import { LifecycleHealthTiles } from '@/components/dashboard/LifecycleHealthTiles';

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  getDashboardLifecycle.mockReset();
  getDashboardHealth.mockReset();
  getDashboardHealth.mockResolvedValue({
    completeness_score: 88,
    missing_metadata: 3,
    outdated_components: 2,
  });
});

describe('LifecycleHealthTiles', () => {
  it('renders lifecycle dashboard counts and recommended upgrades', async () => {
    getDashboardLifecycle.mockResolvedValue({
      total_components: 12,
      supported_count: 5,
      eol_count: 2,
      eos_count: 1,
      eof_count: 1,
      deprecated_count: 2,
      unsupported_count: 1,
      unknown_count: 3,
      eol_soon_count: 1,
      stale_lifecycle_count: 1,
      eol_components: 2,
      eos_upcoming: 1,
      unsupported: 2,
      top_risky_components: [],
      recommended_upgrades: [
        {
          id: 10,
          name: 'nodejs',
          version: '18.0.0',
          lifecycle_status: 'EOL',
          recommended_version: '22.0.0',
        },
      ],
    });

    render(wrap(<LifecycleHealthTiles />));

    expect(await screen.findByText('nodejs')).toBeInTheDocument();
    expect(screen.getAllByText('2').length).toBeGreaterThan(0);
    expect(screen.getByText('Supported')).toBeInTheDocument();
    expect(screen.getByText('Stale Data')).toBeInTheDocument();
    expect(screen.getByText('Recommended Upgrades')).toBeInTheDocument();
    expect(screen.getByText('22.0.0')).toBeInTheDocument();
    expect(screen.getByText('88%')).toBeInTheDocument();
  });

  it('renders lifecycle error state', async () => {
    getDashboardLifecycle.mockRejectedValue(new Error('boom'));

    render(wrap(<LifecycleHealthTiles />));

    expect(await screen.findByText(/Lifecycle metrics could not be loaded/i)).toBeInTheDocument();
  });

  it('renders lifecycle empty state', async () => {
    getDashboardLifecycle.mockResolvedValue({
      total_components: 0,
      supported_count: 0,
      eol_count: 0,
      eos_count: 0,
      eof_count: 0,
      deprecated_count: 0,
      unsupported_count: 0,
      unknown_count: 0,
      eol_soon_count: 0,
      stale_lifecycle_count: 0,
      eol_components: 0,
      eos_upcoming: 0,
      unsupported: 0,
      top_risky_components: [],
      recommended_upgrades: [],
    });

    render(wrap(<LifecycleHealthTiles />));

    expect(await screen.findByText(/No component lifecycle data is available/i)).toBeInTheDocument();
  });
});
