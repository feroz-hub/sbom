// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ComponentVexManager } from './ComponentVexManager';
import type { SBOMComponent, VexStatement } from '@/types';
import { getComponentVulnerabilities, getVexOverrideHistory } from '@/lib/api';
vi.mock('@/lib/api', () => ({ getComponentVulnerabilities: vi.fn(), getVexOverrideHistory: vi.fn() }));
const component = { id: 1, name: 'log4j-core', version: '2.17.1' } as SBOMComponent;
const statement = (vulnerability_id: string, status: string, id: number) => ({ id, component_id: 1, sbom_id: 42,
  vulnerability_id, status, source_name: 'Manual VEX Override', created_at: '2026-01-01' }) as VexStatement;
const decisions = [statement('CVE-2026-0001', 'affected', 1), statement('CVE-2026-0002', 'not_affected', 2), statement('CVE-2026-0003', 'fixed', 3)];
const onDecision = vi.fn();
const wrap = (node: React.ReactNode) => <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{node}</QueryClientProvider>;
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getComponentVulnerabilities).mockImplementation(async (sbomId, componentId) => ({ tenant_id: 1, sbom_id: sbomId,
    component_id: componentId, component_name: 'log4j-core', component_version: '2.17.1',
    vulnerabilities: componentId === 1 ? decisions.map(d => ({ vulnerability_id: d.vulnerability_id, severity: 'HIGH',
      findings: [], current_decision: d })) : [{ vulnerability_id: 'VENDOR-42', severity: null, findings: [], current_decision: null }] }));
  vi.mocked(getVexOverrideHistory).mockResolvedValue({ component_id: 1, vulnerability_id: 'CVE-2026-0001',
    current_decision: decisions[0], history: [], statements: [decisions[0], { ...decisions[0], id: 0, status: 'under_investigation', source_name: 'Vendor' }] });
});
it('shows independent rows and edits only the selected CVE', async () => {
  render(wrap(<ComponentVexManager sbomId={42} component={component} canEdit onClose={vi.fn()} onDecision={onDecision} />));
  const row = (await screen.findByText('CVE-2026-0002')).closest('tr')!;
  expect(within(row).getByText('not_affected')).toBeInTheDocument();
  fireEvent.click(within(row).getByRole('button', { name: 'Edit' }));
  expect(onDecision).toHaveBeenCalledWith('CVE-2026-0002', decisions[1]);
  expect(screen.getByText('affected')).toBeInTheDocument();
  expect(screen.getByText('fixed')).toBeInTheDocument();
});
it('loads only the new component when component selection changes', async () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = (id: number) => <QueryClientProvider client={qc}><ComponentVexManager key={id} sbomId={42}
    component={{ ...component, id }} canEdit onClose={vi.fn()} onDecision={onDecision} /></QueryClientProvider>;
  const { rerender } = render(view(1));
  await screen.findByText('CVE-2026-0001');
  rerender(view(2));
  await screen.findByText('VENDOR-42');
  expect(screen.queryByText('CVE-2026-0001')).not.toBeInTheDocument();
  expect(getComponentVulnerabilities).toHaveBeenLastCalledWith(42, 2, expect.any(AbortSignal));
});
it('offers a separate manual vulnerability action and scoped full history', async () => {
  render(wrap(<ComponentVexManager sbomId={42} component={component} canEdit onClose={vi.fn()} onDecision={onDecision} />));
  fireEvent.click(screen.getByRole('button', { name: 'Add Vulnerability Manually' }));
  expect(onDecision).toHaveBeenCalledWith('', undefined, true);
  const row = (await screen.findByText('CVE-2026-0001')).closest('tr')!;
  fireEvent.click(within(row).getByRole('button', { name: 'History' }));
  await screen.findByText('Current VEX Decision');
  expect(getVexOverrideHistory).toHaveBeenCalledWith(1, 'CVE-2026-0001', expect.any(AbortSignal), 42);
  await waitFor(() => expect(screen.getByText(/under_investigation · Vendor/)).toBeInTheDocument());
  expect(screen.queryByText('CVE-2026-0002')).not.toBeInTheDocument();
});
