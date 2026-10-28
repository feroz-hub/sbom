// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const api = vi.hoisted(() => ({ getLogicalSbom: vi.fn(), getLogicalSbomVersions: vi.fn() }));
const analyze = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', async (original) => ({ ...(await original<typeof import('@/lib/api')>()), ...api }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: '1', hasPermission: () => true }) }));
vi.mock('@/hooks/useAnalysisStream', () => ({ useAnalysisStream: (id: number) => ({ state: { phase: 'idle' }, startAnalysis: (args: unknown) => analyze(id, args) }) }));
vi.mock('./SbomStatusBadge', () => ({ SbomStatusBadge: () => <span>Not analyzed</span> }));
import { LogicalSbomHistory } from './LogicalSbomHistory';
const versions = [
  { id: 3, sbom_name: 'Backend', sbom_version: '1.10', productver: '3.2.0', status: 'validated', lifecycle_status: 'ACTIVE' },
  { id: 2, sbom_name: 'Backend', sbom_version: '1.9', productver: '3.2.0', status: 'validated', lifecycle_status: 'ACTIVE' },
  { id: 1, sbom_name: 'Backend', sbom_version: '1.0', productver: '3.1.0', status: 'validated', lifecycle_status: 'INACTIVE' },
];
function renderHistory() { return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><LogicalSbomHistory id={7} /></QueryClientProvider>); }
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); api.getLogicalSbom.mockResolvedValue({ id: 7, name: 'Backend SBOM', product_id: 4, latest_version: versions[0] }); api.getLogicalSbomVersions.mockResolvedValue(versions); });
describe('Logical SBOM version history', () => {
  it('shows historical revisions, independent product versions and the latest badge', async () => { renderHistory(); expect(await screen.findByRole('heading', { name: 'Backend SBOM' })).toBeInTheDocument(); expect(screen.getByRole('link', { name: '1.10' })).toHaveAttribute('href', '/sboms/3'); expect(screen.getByRole('link', { name: '1.0' })).toHaveAttribute('href', '/sboms/1'); expect(screen.getByText('Latest')).toBeInTheDocument(); expect(screen.getByText('3.1.0')).toBeInTheDocument(); expect(screen.getAllByText('3.2.0')).toHaveLength(2); });
  it('runs analysis against the selected revision and disables inactive revisions', async () => { renderHistory(); const link = await screen.findByRole('link', { name: '1.9' }); await userEvent.click(within(link.closest('tr')!).getByRole('button', { name: 'Run Analysis' })); expect(analyze).toHaveBeenCalledWith(2, expect.anything()); const old = screen.getByRole('link', { name: '1.0' }); expect(within(old.closest('tr')!).getByRole('button', { name: 'Run Analysis' })).toBeDisabled(); });
  it('shows errors without displaying another group history', async () => { api.getLogicalSbom.mockRejectedValue(new Error('Not found')); renderHistory(); expect(await screen.findByText('Not found')).toBeInTheDocument(); expect(screen.queryByRole('link', { name: '1.10' })).not.toBeInTheDocument(); });
});
