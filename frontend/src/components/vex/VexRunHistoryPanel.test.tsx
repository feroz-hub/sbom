// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { VexRunHistoryPanel } from './VexRunHistoryPanel';

const api = vi.hoisted(() => ({getVexAnalysisRuns: vi.fn(), getVexRunSnapshot: vi.fn()}));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/useAuth', () => ({useAuth: () => ({activeTenantId: 1})}));
beforeEach(() => {
  vi.clearAllMocks();
  api.getVexAnalysisRuns.mockResolvedValue({items: [{id: 5, display_id: 5, run_status: 'FINDINGS', completed_on: '2026-10-09', is_current: true}]});
});
function view() {
  render(<QueryClientProvider client={new QueryClient({defaultOptions: {queries: {retry: false}}})}><VexRunHistoryPanel sbomId={3} /></QueryClientProvider>);
}
it('shows immutable prior decisions and assignments for a selected run', async () => {
  api.getVexRunSnapshot.mockResolvedValue({total: 1, snapshot_available: true, obsolete: false, items: [{investigation_id: 1, canonical_vulnerability_id: 'CVE-2026-1000', component_name: 'lib', component_version: '1', effective_status: 'NOT_AFFECTED', reconciliation_status: 'MATCHED', assigned_to: 'membership:7', reviewed_by: 'Analyst'}]});
  view();
  await screen.findByRole('option', {name: /Run #5/});
  await userEvent.selectOptions(screen.getByLabelText('Historical analysis run'), '5');
  expect(await screen.findByText(/Previous assignment: membership:7/)).toBeInTheDocument();
  expect(screen.getByText('NOT_AFFECTED · MATCHED')).toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Open original analysis evidence'})).toHaveAttribute('href', '/analysis/5');
});
it('discloses missing legacy snapshots rather than inventing historical decisions', async () => {
  api.getVexRunSnapshot.mockResolvedValue({total: 0, snapshot_available: false, obsolete: true, items: []});
  view();
  await screen.findByRole('option', {name: /Run #5/});
  await userEvent.selectOptions(screen.getByLabelText('Historical analysis run'), '5');
  expect(await screen.findByText(/Legacy decisions are not reconstructed or inferred/)).toBeInTheDocument();
  expect(screen.getByText(/cannot supply current security posture/)).toBeInTheDocument();
});
