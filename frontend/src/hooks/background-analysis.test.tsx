// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { useBackgroundAnalysis } from './useBackgroundAnalysis';
import { getStillPendingAnalyses } from '@/lib/pendingAnalysis';
const state = vi.hoisted(() => ({ tenant: '1', loading: false, request: vi.fn(), toast: vi.fn(), update: vi.fn() }));
vi.mock('./useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => ({ ...authorizedAuth(), activeTenantId: state.tenant, isLoading: state.loading }) }; });
vi.mock('./useToast', () => ({ useToast: () => ({ showToast: state.toast, updateToast: state.update }) }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock('@/lib/api', async original => ({ ...(await original<typeof import('@/lib/api')>()), analyzeSbom: (...args: unknown[]) => state.request(...args) }));
let qc: QueryClient;
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
beforeEach(() => { vi.clearAllMocks(); sessionStorage.clear(); state.tenant = '1'; state.loading = false; qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, retry: false } } }); });
it.each(['switch', 'logout'])('old analysis callback cannot alter caches after %s', async action => {
  let resolve!: (value: unknown) => void; state.request.mockImplementation(() => new Promise(done => { resolve = done; }));
  qc.setQueryData(['sboms'], [{ id: 5 }]); qc.setQueryData(['sboms', 'dashboard-scope', 1], [{ id: 5 }]);
  const hook = renderHook(() => useBackgroundAnalysis(), { wrapper });
  act(() => hook.result.current.triggerBackgroundAnalysis(5, 'SBOM'));
  expect(qc.getQueryData<Array<{ _analysisStatus?: string }>>(['sboms', 'dashboard-scope', 1])?.[0]._analysisStatus).toBe('ANALYSING');
  state.tenant = action === 'switch' ? '2' : ''; state.loading = action === 'logout'; hook.rerender(); qc.clear();
  await act(async () => { resolve({ run_status: 'FINDINGS', runId: 8, total_findings: 2 }); });
  expect(state.update).not.toHaveBeenCalled(); expect(qc.getQueryCache().getAll()).toHaveLength(0); hook.unmount();
});
it('queued acknowledgement retains tracking and does not report completion', async () => {
  state.request.mockResolvedValue({ run_status: 'PENDING', runId: 8 });
  const hook = renderHook(() => useBackgroundAnalysis(), { wrapper });
  await act(async () => { hook.result.current.triggerBackgroundAnalysis(5, 'SBOM'); });
  expect(getStillPendingAnalyses('1:00000000-0000-4000-8000-000000000001')).toHaveLength(1); expect(state.update).not.toHaveBeenCalled(); hook.unmount(); qc.clear();
});
it('network failure retains recovery and last known findings rather than writing a false terminal result', async () => {
  state.request.mockRejectedValue(new Error('network failed'));
  qc.setQueryData(['sboms'], [{ id: 5, latest_analysis: { finding_count: 81 } }]);
  qc.setQueryData(['findings-enriched', 7], ['previous findings']);
  const hook = renderHook(() => useBackgroundAnalysis(), { wrapper });
  await act(async () => { hook.result.current.triggerBackgroundAnalysis(5, 'SBOM'); });
  expect(getStillPendingAnalyses('1:00000000-0000-4000-8000-000000000001')).toHaveLength(1);
  expect(qc.getQueryData<Array<{ latest_analysis: { finding_count: number } }>>(['sboms'])?.[0].latest_analysis.finding_count).toBe(81);
  expect(qc.getQueryState(['findings-enriched', 7])?.isInvalidated).toBe(false);
  expect(state.update.mock.calls[0][2]).toBe('error'); hook.unmount(); qc.clear();
});
