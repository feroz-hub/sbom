// @vitest-environment jsdom
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { act, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { useAnalysisTerminal } from './useAnalysisTerminal';
import { reconcileAnalysisTerminal, isActiveAnalysis, isTerminalAnalysis } from '@/lib/analysisSync';
vi.mock('./useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => ({ ...authorizedAuth(), activeTenantId: '1' }) }; });
let qc: QueryClient;
beforeEach(() => { qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, retry: false } } }); });
function Probe({ status }: { status: string }) {
  useAnalysisTerminal({ id: 8, sbom_id: 5, run_status: status });
  const query = useQuery({ queryKey: ['findings-enriched', 8, 'HIGH'], queryFn: async () => ['partial finding'] });
  return <output>Findings: {query.data?.length}</output>;
}
it.each(['OK', 'FINDINGS', 'PARTIAL', 'ERROR', 'INTERRUPTED', 'NO_DATA', 'CANCELLED'])('terminal %s refreshes final findings and stops active classification', async status => {
  qc.setQueryData(['findings-enriched', 8, 'HIGH'], []); qc.setQueryData(['findings-enriched', 8, 'LOW'], []);
  qc.setQueryData(['findings-enriched', 99], 'other run'); qc.setQueryData(['vex-run-snapshot', 5, 8], 'immutable');
  const wrap = (value: string) => <QueryClientProvider client={qc}><Probe status={value} /></QueryClientProvider>;
  const mounted = render(wrap('RUNNING')); expect(screen.getByText('Findings: 0')).toBeInTheDocument();
  await act(async () => { mounted.rerender(wrap(status)); });
  expect(await screen.findByText('Findings: 1')).toBeInTheDocument(); expect(isActiveAnalysis(status)).toBe(false); expect(isTerminalAnalysis(status)).toBe(true);
  expect(qc.getQueryState(['findings-enriched', 8, 'LOW'])?.isInvalidated).toBe(true);
  expect(qc.getQueryState(['findings-enriched', 99])?.isInvalidated).toBe(false); expect(qc.getQueryState(['vex-run-snapshot', 5, 8])?.isInvalidated).toBe(false);
  expect(await reconcileAnalysisTerminal(qc, { scope: '1:00000000-0000-4000-8000-000000000001', runId: 8, sbomId: 5, status, isCurrent: () => true })).toBe(false); mounted.unmount(); qc.clear();
});
it('already-terminal runs refresh cached findings on mount; obsolete principal events are ignored', async () => {
  qc.setQueryData(['findings-enriched', 8, 'HIGH'], []);
  const mounted = render(<QueryClientProvider client={qc}><Probe status="FINDINGS" /></QueryClientProvider>);
  expect(await screen.findByText('Findings: 1')).toBeInTheDocument();
  expect(await reconcileAnalysisTerminal(qc, { scope: 'old', runId: 9, status: 'ERROR', isCurrent: () => false })).toBe(false);
  expect(qc.getQueryData(['analysis-terminal-sync', 'old', 9])).toBeUndefined(); mounted.unmount(); qc.clear();
});
it('actual conditional run polling performs one terminal refresh and then stops', async () => {
  vi.useFakeTimers();
  let status = 'RUNNING'; const fetchRun = vi.fn(async () => ({ id: 8, sbom_id: 5, run_status: status }));
  const fetchFindings = vi.fn(async () => status === 'RUNNING' ? [] : ['final']);
  function PollingProbe() {
    const run = useQuery({ queryKey: ['run', 8], queryFn: fetchRun, refetchInterval: query => isActiveAnalysis(query.state.data?.run_status) ? 3000 : false });
    useAnalysisTerminal(run.data);
    const findings = useQuery({ queryKey: ['findings-enriched', 8], queryFn: fetchFindings });
    return <output>{run.data?.run_status}: {findings.data?.length}</output>;
  }
  const mounted = render(<QueryClientProvider client={qc}><PollingProbe /></QueryClientProvider>);
  await act(async () => { await vi.advanceTimersByTimeAsync(20); }); status = 'PARTIAL';
  await act(async () => { await vi.advanceTimersByTimeAsync(3020); });
  expect(screen.getByText('PARTIAL: 1')).toBeInTheDocument(); expect(fetchFindings).toHaveBeenCalledTimes(2);
  const calls = fetchRun.mock.calls.length; await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
  expect(fetchRun).toHaveBeenCalledTimes(calls); mounted.unmount(); qc.clear(); vi.useRealTimers();
});
