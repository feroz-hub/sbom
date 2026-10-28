// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PortfolioHealth, DashboardOperations, SeverityBars, runOutcome } from './PortfolioOverview';
import { LifetimeStats } from './LifetimeStats/LifetimeStats';
import { PortfolioTrend } from './PortfolioTrend';

const mocks = vi.hoisted(() => ({ findings: vi.fn(), runs: vi.fn(), trend: vi.fn(), permission: true }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ hasPermission: () => mocks.permission }) }));
vi.mock('@/lib/api', () => ({ getAnalysisConfig: async () => ({cve_modal_enabled:true}), getDashboardPriorityFindings: (...args: unknown[]) => mocks.findings(...args), getDashboardRuns: (...args: unknown[]) => mocks.runs(...args), getDashboardTrend: (...args: unknown[]) => mocks.trend(...args) }));
vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({ CveDetailDialog: () => null }));
vi.mock('./FindingsTrendChart/FindingsTrendChart', () => ({ FindingsTrendChart: ({data}: {data?: {days?: number}}) => <p>Trend days: {data?.days}</p> }));
const scope = { projectId: null, applicationId: null, sbomId: null };
function wrap(node: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient({defaultOptions: {queries: {retry: false}}})}>{node}</QueryClientProvider>);
}
beforeEach(() => { mocks.permission = true; mocks.findings.mockReset().mockResolvedValue({items: []}); mocks.runs.mockReset().mockResolvedValue([]); mocks.trend.mockReset().mockResolvedValue({days: 7}); });

describe('Portfolio overview', () => {
  it('labels completeness honestly and keeps overlapping lifecycle counts independent', () => {
    wrap(<PortfolioHealth loading={false} hasInventory health={{completeness_score: 82, missing_metadata: 11}} lifecycle={{eol_components: 5, unsupported: 5}} vex={{affected_count: 1, under_investigation_count: 108, vulnerabilities_requiring_action: 109}} />);
    expect(screen.getByText('82%')).toBeInTheDocument();
    expect(screen.getByText(/SBOM Completeness/)).toBeInTheDocument();
    expect(screen.getByText(/may overlap/)).toBeInTheDocument();
    expect(screen.getByText('Requires action').parentElement).toHaveTextContent('109');
    expect(screen.queryByText(/quality rating/i)).not.toBeInTheDocument();
  });
  it('does not convert absent health into a zero score', () => {
    wrap(<PortfolioHealth loading={false} hasInventory={false} />);
    expect(screen.getByText('No completeness data available')).toBeInTheDocument();
    expect(screen.queryByText('0%')).not.toBeInTheDocument();
  });
  it('preserves findings outcomes and exposes partial coverage without calling findings a failure', () => {
    expect(runOutcome({run_status:'FINDINGS', query_error_count:0, source:'NVD'})).toBe('Completed · findings detected');
    expect(runOutcome({run_status:'FINDINGS', query_error_count:4, source:'NVD'})).toBe('Incomplete coverage');
    expect(runOutcome({run_status:'PARTIAL', query_error_count:0, source:'NVD'})).toBe('Incomplete coverage');
    expect(runOutcome({run_status:'ERROR', query_error_count:0, source:'NVD'})).toBe('Analysis failed');
  });
  it('bars include unknown and drill into populated scored tiers only', () => {
    const select = vi.fn();
    wrap(<SeverityBars loading={false} data={{critical:17,high:58,medium:31,low:2,unknown:4}} onSelect={select} />);
    expect(screen.getByText('Unknown: 4')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', {name:'High: 58'}));
    expect(select).toHaveBeenCalledWith('high');
  });
  it('operational requests carry scope and tenant-specific query keys', async () => {
    mocks.findings.mockResolvedValue({items:[{id:1,analysis_run_id:8,vuln_id:'CVE-2026-1234',component_name:'library',component_version:'1',severity:'HIGH',score:8}]});
    wrap(<DashboardOperations scope={scope} tenantId="1" />);
    expect(await screen.findByRole('link', {name:'CVE-2026-1234'})).toHaveAttribute('href','/analysis/8');
    expect(mocks.findings).toHaveBeenCalledWith(scope, expect.any(AbortSignal));
    expect(screen.getByRole('heading', {name:'Recent analysis runs'})).toBeInTheDocument();
  });
  it('read restrictions do not offer operations or make requests', () => {
    mocks.permission = false;
    wrap(<DashboardOperations scope={scope} tenantId="1" />);
    expect(screen.queryByRole('heading', {name:'High-priority findings'})).not.toBeInTheDocument();
    expect(mocks.findings).not.toHaveBeenCalled();
  });
  it('switches trend period using the same hierarchy without inventing history', async () => {
    wrap(<PortfolioTrend initial={{days:30} as never} scope={scope} tenantId="1" />);
    expect(mocks.trend).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Observation window'), {target:{value:'7'}});
    await waitFor(() => expect(mocks.trend).toHaveBeenCalledWith(7, expect.any(AbortSignal), scope));
    expect(await screen.findByText('Trend days: 7')).toBeInTheDocument();
  });
  it("tenant switches never retain another tenant's findings", async () => {
    mocks.findings.mockResolvedValueOnce({items:[{id:1,analysis_run_id:8,vuln_id:'CVE-TENANT-A',component_name:'A',component_version:'1',severity:'HIGH',score:8}]}).mockResolvedValueOnce({items:[{id:2,analysis_run_id:9,vuln_id:'CVE-TENANT-B',component_name:'B',component_version:'1',severity:'HIGH',score:8}]});
    const client = new QueryClient({defaultOptions:{queries:{retry:false}}});
    const view = render(<QueryClientProvider client={client}><DashboardOperations key="A" scope={scope} tenantId="A" /></QueryClientProvider>);
    expect(await screen.findByText('CVE-TENANT-A')).toBeInTheDocument();
    view.rerender(<QueryClientProvider client={client}><DashboardOperations key="B" scope={scope} tenantId="B" /></QueryClientProvider>);
    expect(screen.queryByText('CVE-TENANT-A')).not.toBeInTheDocument();
    expect(await screen.findByText('CVE-TENANT-B')).toBeInTheDocument();
    expect(client.getQueryData(['dashboard-priority-findings','A',null,null,null])).toBeDefined();
  });
  it('API failures show retryable unavailable state instead of empty records', async () => {
    mocks.findings.mockRejectedValue(new Error('Unavailable'));
    wrap(<DashboardOperations scope={scope} tenantId="1" />);
    expect(await screen.findByRole('alert', {}, {timeout:3000})).toHaveTextContent('Data unavailable');
    mocks.findings.mockResolvedValue({items:[]});
    fireEvent.click(screen.getByRole('button',{name:'Retry'}));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });

  it('completed run KPI reads successful runs rather than all executed runs', () => {
    wrap(<LifetimeStats completedOnly isLoading={false} findingsTotal={108} data={{sboms_scanned_total:2,projects_total:2,runs_executed_total:4,runs_completed_total:2,runs_executed_this_week:4,findings_surfaced_total:108,findings_resolved_total:0,first_run_at:'2026-10-05',days_monitoring:3}} />);
    expect(screen.getByText('Analysis runs completed').parentElement).toHaveTextContent('2');
    expect(screen.getByText('Analysis runs completed').parentElement).not.toHaveTextContent('4 this week');
  });
  it('absent completed-run evidence is not displayed as zero', () => {
    wrap(<LifetimeStats completedOnly isLoading={false} findingsTotal={0} data={undefined} />);
    expect(screen.getByText('Analysis runs completed').parentElement).toHaveTextContent('—');
  });

});
