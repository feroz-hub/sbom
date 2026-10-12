// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useSbomsList } from './useSbomsList';
import { usePendingAnalysisRecovery } from './usePendingAnalysisRecovery';
import { addPendingAnalysis, getStillPendingAnalyses } from '@/lib/pendingAnalysis';
import type { DashboardFilterScope } from '@/lib/api';
const state = vi.hoisted(() => ({ tenant: '1', loading: false, runs: vi.fn(), sboms: vi.fn() }));
vi.mock('./useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => ({ ...authorizedAuth(), activeTenantId: state.tenant, isLoading: state.loading }) }; });
vi.mock('@/lib/api', async original => ({ ...(await original<typeof import('@/lib/api')>()), getRuns: (...args: unknown[]) => state.runs(...args), getSboms: (...args: unknown[]) => state.sboms(...args) }));
let qc: QueryClient;
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
const row = (status: string) => ({ id: 5, latest_analysis: { run_id: 8, status, result: status === 'RUNNING' ? 'running' : 'completed', finding_count: 2 } });
beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear(); state.tenant = '1'; state.loading = false;
  qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
  state.sboms.mockResolvedValue([row('RUNNING')]); state.runs.mockResolvedValue([]);
});
afterEach(() => { qc.clear(); vi.useRealTimers(); });
it.each([undefined, { projectId: 1, applicationId: null, sbomId: null }, { projectId: 1, applicationId: 2, sbomId: null }, { projectId: 1, applicationId: 2, sbomId: 5 }] as Array<DashboardFilterScope | undefined>)('conditional list polling tracks terminal results with scope %s', async scope => {
  vi.useFakeTimers();
  const { result, unmount } = renderHook(() => useSbomsList({ scope }), { wrapper });
  await act(async () => { await vi.advanceTimersByTimeAsync(20); });
  expect(result.current.data?.[0].latest_analysis?.status).toBe('RUNNING');
  state.sboms.mockResolvedValue([row('PARTIAL')]);
  await act(async () => { await vi.advanceTimersByTimeAsync(3020); });
  expect(result.current.data?.[0].latest_analysis?.status).toBe('PARTIAL');
  expect(state.sboms.mock.calls[0][3]).toEqual(scope);
  const count = state.sboms.mock.calls.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
  expect(state.sboms).toHaveBeenCalledTimes(count); unmount();
});
it.each(['FINDINGS', 'ERROR', 'CANCELLED', 'INTERRUPTED'])('recovery retains active marker then reconciles %s', async status => {
  addPendingAnalysis(5, 'test', '1:1', 8);
  state.runs.mockResolvedValue([{ id: 8, sbom_id: 5, run_status: 'RUNNING' }]);
  const mounted = renderHook(() => usePendingAnalysisRecovery(), { wrapper });
  await waitFor(() => expect(state.runs).toHaveBeenCalledTimes(1));
  expect(getStillPendingAnalyses('1:1')).toHaveLength(1);
  state.runs.mockResolvedValue([{ id: 8, sbom_id: 5, run_status: status }]);
  await act(async () => { await qc.refetchQueries({ queryKey: ['pending-analysis-recovery'] }); });
  await waitFor(() => expect(getStillPendingAnalyses('1:1')).toHaveLength(0));
  expect(qc.getQueryData(['analysis-terminal-sync', '1:1', 8])).toBe(status); mounted.unmount();
});
it.each(['missing', 'network'])('recent %s result retains marker; expired unresolved marker is removed', async failure => {
  addPendingAnalysis(5, 'test', '1:1', 8);
  if (failure === 'network') state.runs.mockRejectedValue(new Error('offline'));
  const mounted = renderHook(() => usePendingAnalysisRecovery(), { wrapper });
  await waitFor(() => expect(state.runs).toHaveBeenCalledTimes(1)); expect(getStillPendingAnalyses('1:1')).toHaveLength(1);
  const data = JSON.parse(sessionStorage.getItem('pending_analyses')!); data['1:1:5'].checkedAt = Date.now() - 240000;
  sessionStorage.setItem('pending_analyses', JSON.stringify(data));
  await act(async () => { await qc.refetchQueries({ queryKey: ['pending-analysis-recovery'] }); });
  await waitFor(() => expect(getStillPendingAnalyses('1:1')).toHaveLength(0)); mounted.unmount();
});
it.each(['switch', 'logout'])('in-flight recovery cannot write after %s', async action => {
  addPendingAnalysis(5, 'test', '1:1', 8);
  let resolve!: (value: unknown) => void; state.runs.mockImplementation(() => new Promise(done => { resolve = done; }));
  const mounted = renderHook(() => usePendingAnalysisRecovery(), { wrapper });
  await waitFor(() => expect(state.runs).toHaveBeenCalled());
  state.tenant = action === 'switch' ? '2' : ''; state.loading = action === 'logout';
  mounted.rerender(); qc.clear();
  await act(async () => { resolve([{ id: 8, sbom_id: 5, run_status: 'FINDINGS' }]); });
  expect(qc.getQueryData(['analysis-terminal-sync', '1:1', 8])).toBeUndefined();
  expect(getStillPendingAnalyses('1:1')).toHaveLength(1); mounted.unmount();
});
it('a previous completed run cannot clear an unidentified new submission', async () => {
  addPendingAnalysis(5, 'test', '1:1');
  state.runs.mockResolvedValue([{ id: 7, sbom_id: 5, run_status: 'OK', started_on: new Date(Date.now() - 60000).toISOString() }]);
  const mounted = renderHook(() => usePendingAnalysisRecovery(), { wrapper });
  await waitFor(() => expect(state.runs).toHaveBeenCalled()); expect(getStillPendingAnalyses('1:1')).toHaveLength(1);
  expect(qc.getQueryData(['analysis-terminal-sync', '1:1', 7])).toBeUndefined(); mounted.unmount();
});
it('staggered observers share one list polling timer and hand off after owner unmount', async () => {
  vi.useFakeTimers();
  const first = renderHook(() => useSbomsList(), { wrapper });
  await act(async () => { await vi.advanceTimersByTimeAsync(100); });
  const second = renderHook(() => useSbomsList(), { wrapper });
  await act(async () => { await vi.advanceTimersByTimeAsync(3100); });
  expect(state.sboms).toHaveBeenCalledTimes(2);
  first.unmount();
  await act(async () => { await vi.advanceTimersByTimeAsync(3100); });
  expect(state.sboms).toHaveBeenCalledTimes(3); second.unmount();
});
