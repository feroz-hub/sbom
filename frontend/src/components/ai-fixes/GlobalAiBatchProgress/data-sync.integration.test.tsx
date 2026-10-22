// @vitest-environment jsdom
import { useContext, useEffect } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { AiBatchProgressProvider } from './AiBatchProgressProvider';
import { AiBatchProgressContext } from './AiBatchProgressContext';
import { GlobalAiBatchBanner } from './GlobalAiBatchBanner';
import { useCancelAiBatch, useCancelAiFixes, useTriggerScopedAiFixes, useAiBatchProgress } from '@/hooks/useAiFix';
import { useGlobalAiBatchProgress } from './useGlobalAiBatchProgress';
import { makeBatchProgress } from '../__tests__/test-utils';
import type { AiBatchProgress } from '@/types/ai';
const state = vi.hoisted(() => ({ tenant: '1', userId: '00000000-0000-4000-8000-000000000001', ready: true }));
const api = vi.hoisted(() => ({ getRunAiBatch: vi.fn(), getRunAiFixProgress: vi.fn(), cancelRunAiBatch: vi.fn(), cancelRunAiFixes: vi.fn(), triggerRunAiFixes: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: state.ready ? { userId: state.userId } : null, activeTenantId: state.tenant, isLoading: false, hasPermission: () => state.ready }) }));
vi.mock('@/lib/auth', () => ({ getActiveTenantId: () => state.tenant }));
vi.mock('next/navigation', () => ({ usePathname: () => '/' }));
vi.mock('@/lib/api', async original => ({ ...await original<typeof import('@/lib/api')>(), ...api, aiFixStreamUrl: () => '/legacy-stream', aiFixBatchStreamUrl: () => '/batch-stream' }));
class FakeSource {
  static all: FakeSource[] = [];
  handlers = new Map<string, (event: MessageEvent) => void>();
  onerror: (() => void) | null = null; closed = false;
  constructor() { FakeSource.all.push(this); }
  addEventListener(name: string, fn: (event: MessageEvent) => void) { this.handlers.set(name, fn); }
  close() { this.closed = true; }
  send(p: AiBatchProgress) { this.handlers.get('progress')?.({ data: JSON.stringify(p) } as MessageEvent); }
}
const keys = [['ai-fix-list', "00000000-0000-4000-8000-00000000002a"], ['ai-fix', 10, null], ['ai-batch-list', "00000000-0000-4000-8000-00000000002a"], ['ai-settings', 'usage'], ['ai-usage-trend', 30], ['ai-top-cached', 20]];
let qc: QueryClient; let p: AiBatchProgress; let output = 0; let fetchers: Array<ReturnType<typeof vi.fn<() => Promise<{ generated: number }>>>>;
function Results() {
  const fixes = useQuery({ queryKey: keys[0], queryFn: fetchers[0] });
  const detail = useQuery({ queryKey: keys[1], queryFn: fetchers[1] });
  const history = useQuery({ queryKey: keys[2], queryFn: fetchers[2] });
  const usage = useQuery({ queryKey: keys[3], queryFn: fetchers[3] });
  useQuery({ queryKey: keys[4], queryFn: fetchers[4] }); useQuery({ queryKey: keys[5], queryFn: fetchers[5] });
  return <div data-testid="results">{JSON.stringify([fixes.data, detail.data, history.data, usage.data])}</div>;
}
function Track({ batch = 'batch-a', run = '00000000-0000-4000-8000-00000000002a' }: { batch?: string | null; run?: string }) {
  const register = useContext(AiBatchProgressContext)?.register;
  useEffect(() => { register?.({ runId: run, batchId: batch }); }, [register, run, batch]);
  return null;
}
function Actions({ legacy = false }: { legacy?: boolean }) {
  const cancel = useCancelAiBatch("00000000-0000-4000-8000-00000000002a"); const cancelLegacy = useCancelAiFixes("00000000-0000-4000-8000-00000000002a"); const trigger = useTriggerScopedAiFixes("00000000-0000-4000-8000-00000000002a");
  return <><button onClick={() => (legacy ? cancelLegacy.mutateAsync() : cancel.mutateAsync('batch-a')).catch(() => {})}>Dedicated cancel</button><button onClick={() => trigger.mutate({})}>Enqueue</button></>;
}
function wrap(ui: React.ReactNode) { return <QueryClientProvider client={qc}><ToastProvider>{ui}</ToastProvider></QueryClientProvider>; }
beforeEach(() => {
  state.tenant = '1'; state.userId = '00000000-0000-4000-8000-000000000001'; state.ready = true; output = 0; FakeSource.all = []; vi.stubGlobal('EventSource', FakeSource);
  p = makeBatchProgress({ run_id: "00000000-0000-4000-8000-00000000002a", batch_id: 'batch-a', status: 'in_progress', generated: 0, from_cache: 0, failed: 0 });
  qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300000, refetchOnWindowFocus: false, retry: false }, mutations: { retry: false } } });
  fetchers = keys.map(() => vi.fn(async () => ({ generated: output })));
  keys.forEach(key => qc.setQueryData(key, { generated: 0 }));
  qc.setQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-a'], p); qc.setQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a"], p);
  for (const fn of Object.values(api)) fn.mockReset();
  api.getRunAiBatch.mockImplementation(async (_run, batch) => ({ progress: { ...p, batch_id: batch } })); api.getRunAiFixProgress.mockImplementation(async () => p);
  api.cancelRunAiBatch.mockResolvedValue({ run_id: '00000000-0000-4000-8000-00000000002a', batch_id: 'batch-a', cancel_requested: true }); api.cancelRunAiFixes.mockResolvedValue({ run_id: '00000000-0000-4000-8000-00000000002a', cancel_requested: true });
  api.triggerRunAiFixes.mockResolvedValue({ batch_id: 'batch-b', progress: { ...p, batch_id: 'batch-b', status: 'queued' }, enqueued: true });
});
afterEach(() => { cleanup(); qc.clear(); vi.unstubAllGlobals(); vi.useRealTimers(); });
describe('AI generation synchronization', () => {
  it.each(['complete', 'failed', 'cancelled', 'paused_budget'] as const)('SSE %s exposes server-generated partial results without reload and deduplicates repeat events', async status => {
    render(wrap(<AiBatchProgressProvider><Track /><Results /></AiBatchProgressProvider>));
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    await act(async () => {}); output = 2; p = { ...p, status, generated: 2, finished_at: '2026-10-09', last_error: status === 'failed' ? 'Provider failed after partial output' : null };
    act(() => { FakeSource.all[0].send(p); FakeSource.all[0].send(p); });
    await waitFor(() => expect(screen.getByTestId('results')).toHaveTextContent('"generated":2'));
    fetchers.forEach(fn => expect(fn).toHaveBeenCalledTimes(1));
    expect(qc.getQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-a'])).toMatchObject({ status, last_error: p.last_error });
    expect(FakeSource.all[0].closed).toBe(true);
  });
  it('no SSE fallback polls active work, refreshes terminal results, and stops polling', async () => {
    vi.stubGlobal('EventSource', undefined); vi.useFakeTimers();
    render(wrap(<AiBatchProgressProvider><Track /><Results /></AiBatchProgressProvider>));
    await act(async () => {}); output = 3; p = { ...p, status: 'complete', generated: 3 };
    await act(async () => { await vi.advanceTimersByTimeAsync(2001); });
    expect(screen.getByTestId('results')).toHaveTextContent('"generated":3');
    const reads = api.getRunAiBatch.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(api.getRunAiBatch).toHaveBeenCalledTimes(reads); fetchers.forEach(fn => expect(fn).toHaveBeenCalledTimes(1));
  });
  it.each(['tenant', 'logout'])('drops tracked progress and rejects queued callbacks on %s change', async change => {
    let resolve!: (data: { progress: AiBatchProgress }) => void;
    api.getRunAiBatch.mockReturnValue(new Promise(r => { resolve = r; }));
    qc.removeQueries({ queryKey: ['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-a'], exact: true });
    const view = render(wrap(<AiBatchProgressProvider><Track /><Results /></AiBatchProgressProvider>));
    await waitFor(() => expect(FakeSource.all).toHaveLength(1));
    const source = FakeSource.all[0], old = p;
    if (change === 'tenant') state.tenant = '2'; else state.ready = false;
    qc.clear(); view.rerender(wrap(<AiBatchProgressProvider><Results /></AiBatchProgressProvider>));
    await act(async () => { resolve({ progress: { ...old, status: 'complete' } }); source.send({ ...old, status: 'complete' }); });
    expect(source.closed).toBe(true); expect(qc.getQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-a'])).toBeUndefined();
    expect(qc.getQueriesData({ queryKey: ['ai-batch-terminal-sync'] })).toHaveLength(0);
  });
  it('two simultaneous batches retain distinct progress; a later batch still refreshes results', async () => {
    render(wrap(<AiBatchProgressProvider><Track /><Track batch="batch-b" /><Results /></AiBatchProgressProvider>));
    await waitFor(() => expect(FakeSource.all).toHaveLength(2)); await act(async () => {});
    output = 1; act(() => FakeSource.all[0].send({ ...p, status: 'complete' }));
    await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(1));
    expect(qc.getQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-b'])).toMatchObject({ status: 'in_progress', batch_id: 'batch-b' });
    output = 2; act(() => FakeSource.all[1].send({ ...p, batch_id: 'batch-b', status: 'complete' }));
    await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(2)); expect(screen.getByTestId('results')).toHaveTextContent('"generated":2');
  });
  it.each([false, true])('dedicated cancellation refreshes partial outputs without claiming completion (legacy=%s)', async legacy => {
    output = 1; render(wrap(<><Actions legacy={legacy} /><Results /></>));
    fireEvent.click(screen.getByRole('button', { name: 'Dedicated cancel' }));
    await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(1));
    expect(qc.getQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a"]) ).toMatchObject({ status: 'in_progress' });
    expect(screen.getByTestId('results')).toHaveTextContent('"generated":1');
  });
  it.each([403, 409, 500])('failed cancel HTTP %s leaves results and tracking unchanged', async status => {
    api.cancelRunAiBatch.mockRejectedValue(new Error(`HTTP ${status}`));
    render(wrap(<AiBatchProgressProvider><Track /><GlobalAiBatchBanner /><Results /></AiBatchProgressProvider>));
    await screen.findByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a'); fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await screen.findByText('Unable to cancel AI generation. Please try again.');
    expect(screen.getByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a')).toBeInTheDocument(); expect(fetchers[0]).not.toHaveBeenCalled();
  });
  it('banner cancellation uses the dedicated partial result/history/usage contract and retains progress', async () => {
    render(wrap(<AiBatchProgressProvider><Track /><GlobalAiBatchBanner /><Results /></AiBatchProgressProvider>));
    await screen.findByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a'); await act(async () => {}); output = 1;
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(1));
    fetchers.forEach(fn => expect(fn).toHaveBeenCalledTimes(1));
    expect(screen.getByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a')).toBeInTheDocument(); expect(FakeSource.all[0].closed).toBe(false);
  });
  it('successful enqueue seeds queued state/history but does not imply generated output', async () => {
    render(wrap(<><Actions /><Results /></>)); fireEvent.click(screen.getByRole('button', { name: 'Enqueue' }));
    await waitFor(() => expect(fetchers[2]).toHaveBeenCalledTimes(1));
    expect(qc.getQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a", 'batch-b'])).toMatchObject({ status: 'queued' });
    expect(fetchers[0]).not.toHaveBeenCalled(); expect(fetchers[1]).not.toHaveBeenCalled(); expect(fetchers[3]).not.toHaveBeenCalled();
  });
  it('a legacy progress hook reconciles an already terminal authoritative snapshot', async () => {
    output = 1; p = { ...p, status: 'complete' }; qc.removeQueries({ queryKey: ['ai-batch-progress'] });
    function Legacy() { useAiBatchProgress("00000000-0000-4000-8000-00000000002a"); return <Results />; }
    render(wrap(<Legacy />)); await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(1));
    expect(screen.getByTestId('results')).toHaveTextContent('"generated":1');
  });
  it('a global query consumer reconciles terminal progress without a provider', async () => {
    output = 1; p = { ...p, status: 'complete' }; qc.setQueryData(['ai-batch-progress', "00000000-0000-4000-8000-00000000002a"], p);
    function Global() { useGlobalAiBatchProgress("00000000-0000-4000-8000-00000000002a"); return <Results />; }
    render(wrap(<Global />)); await waitFor(() => expect(fetchers[0]).toHaveBeenCalledTimes(1));
  });
  it('context cleanup preserves unrelated form drafts while removing previous progress', async () => {
    const tree = () => wrap(<AiBatchProgressProvider><input aria-label="Unrelated draft" defaultValue="draft" /><Track /><GlobalAiBatchBanner /></AiBatchProgressProvider>);
    const view = render(tree()); await screen.findByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a');
    fireEvent.change(screen.getByLabelText('Unrelated draft'), { target: { value: 'unsaved changes' } });
    state.tenant = '2'; qc.clear(); view.rerender(wrap(<AiBatchProgressProvider><input aria-label="Unrelated draft" defaultValue="draft" /><GlobalAiBatchBanner /></AiBatchProgressProvider>));
    expect(screen.getByLabelText('Unrelated draft')).toHaveValue('unsaved changes');
    expect(screen.queryByTestId('global-ai-batch-row-00000000-0000-4000-8000-00000000002a-batch-a')).not.toBeInTheDocument();
  });
  it('cancel response from a previous tenant cannot invalidate the new tenant cache', async () => {
    let resolve!: (data: { cancel_requested: boolean }) => void;
    api.cancelRunAiBatch.mockReturnValue(new Promise(r => { resolve = r; }));
    const view = render(wrap(<Actions />)); fireEvent.click(screen.getByRole('button', { name: 'Dedicated cancel' }));
    await waitFor(() => expect(api.cancelRunAiBatch).toHaveBeenCalledTimes(1));
    state.tenant = '2'; qc.clear(); qc.setQueryData(['ai-fix-list', "00000000-0000-4000-8000-00000000002a"], { tenant: 2 }); view.rerender(wrap(<Actions />));
    await act(async () => { resolve({ cancel_requested: true }); });
    expect(qc.getQueryState(['ai-fix-list', "00000000-0000-4000-8000-00000000002a"])?.isInvalidated).toBe(false);
    expect(qc.getQueryData(['ai-fix-list', "00000000-0000-4000-8000-00000000002a"])).toEqual({ tenant: 2 });
  });

});
