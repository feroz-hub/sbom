// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { SBOMSource } from '@/types';
import { SbomsTable } from './SbomsTable';

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { roles: ['VIEWER'], isPlatformAdmin: false },
    hasPermission: () => false,
    isLoading: false,
  }),
}));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }),
}));
vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast: vi.fn() }),
}));

const first = {
  id: '00000000-0000-4000-8000-000000000101',
  display_id: 101,
  sbom_name: 'Infusion Pump Controller',
  sbom_type: 1,
  sbom_version: '2.0.0',
  projectid: 12,
  project_name: 'Medical Devices',
  product_id: 22,
  product_name: 'Pump Controller',
  format: 'cyclonedx',
  status: 'validated',
  created_by: 'security@example.com',
  created_on: '2026-10-01T00:00:00Z',
  latest_analysis: null,
} as SBOMSource;

const second = {
  ...first,
  id: '00000000-0000-4000-8000-000000000102',
  display_id: 102,
  sbom_name: 'Gateway Firmware',
  sbom_version: '1.0.1',
  project_name: 'Gateway Security',
  projectid: 13,
  product_name: 'Gateway',
  product_id: 23,
} as SBOMSource;

function mount(sboms: SBOMSource[] = [first, second]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <SbomsTable sboms={sboms} isLoading={false} error={null} />
    </QueryClientProvider>,
  );
}

describe('SBOM inventory redesign regression', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('retains UUID routes, numeric display IDs, version and accessible list sorting', () => {
    mount([first]);
    const table = screen.getByRole('table', { name: 'SBOM inventory table' });
    const id = within(table).getByLabelText('Record ID 101');
    expect(id.closest('a')).toHaveAttribute('href', `/sboms/${first.id}`);
    expect(within(table).getByText('2.0.0')).toBeInTheDocument();
    expect(within(table).getByRole('button', { name: /Sort by Name/i })).toBeInTheDocument();
    expect(within(table).getByRole('checkbox', { name: 'Select all filtered SBOMs' })).toBeInTheDocument();
  });

  it('exposes advanced filters, applies a project scope and clears without losing inventory', () => {
    mount();
    expect(screen.queryByLabelText('Project')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Filters$/ }));
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'Medical Devices' } });
    expect(screen.getByText('1 of 2 SBOMs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove project filter' })).toBeInTheDocument();
    expect(screen.queryByText('Gateway Firmware')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove project filter' }));
    expect(screen.getByText('Gateway Firmware')).toBeInTheDocument();
  });

  it('supports a grid alternative without duplicated table actions or records', () => {
    mount([first]);
    fireEvent.click(screen.getByRole('radio', { name: /Grid/i }));
    expect(screen.queryByRole('table', { name: 'SBOM inventory table' })).not.toBeInTheDocument();
    expect(screen.getByRole('article')).toBeInTheDocument();
    expect(screen.getAllByText('Infusion Pump Controller')).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Actions for SBOM Infusion Pump Controller' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('radio', { name: /List/i }));
    expect(screen.getByRole('table', { name: 'SBOM inventory table' })).toBeInTheDocument();
  });

  it('keeps selected rows and explains why mixed-project FDA exports are disabled', () => {
    mount();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Infusion Pump Controller' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Gateway Firmware' }));
    expect(screen.getByText(/2 selected/)).toBeInTheDocument();
    expect(screen.getByText(/Select SBOMs from one project to generate an FDA report/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }));
    expect(screen.queryByText(/2 selected/)).not.toBeInTheDocument();
  });
});
