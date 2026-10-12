// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAnalysisStream } from './useAnalysisStream';
import { getStillPendingAnalyses } from '@/lib/pendingAnalysis';
const state = vi.hoisted(() => ({ tenant: '1', get: vi.fn() }));
vi.mock('./useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => ({ ...authorizedAuth(), activeTenantId: state.tenant }) }; });
vi.mock('@/lib/api', async original => ({ ...(await original<typeof import('@/lib/api')>()), getRun: (...args: unknown[]) => state.get(...args) }));
let qc: QueryClient;
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
function response(terminal: 'complete' | 'error') {
  const text = `event: progress\ndata: {"phase":"started","runId":8}\n\nevent: ${terminal}\ndata: ${terminal === 'complete' ? '{"runId":8,"status":"PARTIAL","total":2}' : '{"message":"Scanner failed"}'}\n\n`;
  return { ok: true, body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(text)); controller.close(); } }) } as Response;
}
beforeEach(() => { vi.clearAllMocks(); state.tenant = '1'; sessionStorage.clear(); sessionStorage.setItem('sbom_active_tenant_id', '1'); qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, retry: false } } }); });
afterEach(() => { qc.clear(); vi.unstubAllGlobals(); });
it.each(['complete', 'error'] as const)('existing stream %s reconciles authoritative status and clears terminal tracking', async terminal => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(terminal)));
  state.get.mockResolvedValue({ id: 8, run_status: 'ERROR', sbom_id: 5 }); qc.setQueryData(['findings-enriched', 8], []);
  const hook = renderHook(() => useAnalysisStream(5), { wrapper });
  await act(async () => { await hook.result.current.startAnalysis(); });
  await waitFor(() => expect(qc.getQueryData(['analysis-terminal-sync', '1:1', 8])).toBe(terminal === 'complete' ? 'PARTIAL' : 'ERROR'));
  expect(qc.getQueryState(['findings-enriched', 8])?.isInvalidated).toBe(true);
  expect(getStillPendingAnalyses('1:1')).toHaveLength(0); hook.unmount();
});
it('late stream response cannot write into a different tenant context', async () => {
  let resolve!: (value: Response) => void; vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(done => { resolve = done; })));
  const hook = renderHook(() => useAnalysisStream(5), { wrapper });
  let task!: Promise<void>; act(() => { task = hook.result.current.startAnalysis(); });
  state.tenant = '2'; sessionStorage.setItem('sbom_active_tenant_id', '2'); hook.rerender(); qc.clear();
  await act(async () => { resolve(response('complete')); await task; });
  expect(qc.getQueryCache().getAll()).toHaveLength(0); expect(hook.result.current.state.summary).toBeNull(); hook.unmount();
});
