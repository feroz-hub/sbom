/**
 * Hooks for the AI fix surface.
 *
 *   * ``useAiFix`` — read-only cache lookup for one finding (safe to fire
 *     on modal mount), plus ``generate`` and ``regenerate`` mutations
 *     that fire only on explicit user click. Keys the cache on
 *     (findingId, provider) so switching providers in Settings
 *     invalidates per-finding cache entries naturally.
 *
 *   * ``useAiBatchProgress`` — subscribe to a run's batch state. Tries
 *     SSE first (live updates with no polling spend); falls back to
 *     polling every 2s when ``EventSource`` is unavailable or the
 *     stream errors.
 *
 *   * ``useAiSettings`` — providers + pricing + usage summary, joined
 *     into one shape the Settings page consumes.
 */

import { useMutationScope } from './useMutationScope';
import { isAiBatchTerminal, reconcileAiBatchTerminal, invalidateAiBatchCancellation } from '@/lib/aiBatchSync';
import { invalidateAiBatchSurfaces } from '@/lib/queryInvalidation';
import { useEffect, useState } from 'react';
import {
  type QueryClient,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import {
  aiFixStreamUrl,
  cancelRunAiBatch,
  cancelRunAiFixes,
  estimateRunAiFixesScoped,
  generateFindingAiFix,
  getAiUsageSummary,
  getFindingAiFix,
  getRunAiFixProgress,
  listAiPricing,
  listAiProviders,
  listRunAiBatches,
  listRunAiFixes,
  regenerateFindingAiFix,
  triggerRunAiFixes,
} from '@/lib/api';
import { scopeCacheKey } from '@/lib/aiFixScope';
import type {
  AiBatchListResponse,
  AiBatchProgress,
  AiFindingFixEnvelope,
  AiFindingFixListResponse,
  AiFixGenerationScope,
  AiPricingEntry,
  AiProviderInfo,
  AiScopedEstimateResponse,
  AiTriggerBatchRequest,
  AiUsageSummary,
} from '@/types/ai';

// ─── Single-finding ─────────────────────────────────────────────────────────


/** Stable key — exported so callers (modal close, batch completion) can
 *  invalidate without restating the shape. */
export function aiFixQueryKey(findingId: number, providerName?: string | null) {
  return ['ai-fix', findingId, providerName ?? null] as const;
}


export function useAiFix(
  findingId: number | null,
  args: { providerName?: string | null; enabled?: boolean } = {},
) {
  const { providerName = null, enabled = true } = args;
  const qc = useQueryClient();

  // Read-only cache lookup — fires on mount but ``getFindingAiFix``
  // returns ``null`` on 404 instead of throwing, so opening the modal
  // for a finding that has never been generated is silent (no LLM
  // spend, no error UI). Generation only happens via the ``generate``
  // mutation below.
  const query = useQuery<AiFindingFixEnvelope | null>({
    queryKey: aiFixQueryKey(findingId ?? -1, providerName),
    queryFn: ({ signal }) =>
      getFindingAiFix(findingId as number, { providerName }, signal),
    enabled: enabled && findingId != null,
    staleTime: 5 * 60_000,
  });

  const generate = useMutation<AiFindingFixEnvelope, Error, void>({
    mutationFn: () =>
      generateFindingAiFix(findingId as number, { providerName }),
    onSuccess: (data) => {
      qc.setQueryData(aiFixQueryKey(findingId ?? -1, providerName), data);
      // The run-detail "AI fix" column flips from Generate → View when a
      // fix lands. We don't know the runId here, so invalidate the prefix.
      qc.invalidateQueries({ queryKey: ['ai-fix-list'] });
    },
  });

  const regenerate = useMutation<AiFindingFixEnvelope, Error, void>({
    mutationFn: () =>
      regenerateFindingAiFix(findingId as number, { providerName }),
    onSuccess: (data) => {
      qc.setQueryData(aiFixQueryKey(findingId ?? -1, providerName), data);
      qc.invalidateQueries({ queryKey: ['ai-fix-list'] });
    },
  });

  return { ...query, generate, regenerate };
}


// ─── Batch progress ─────────────────────────────────────────────────────────


type SSEAvailable = boolean | null;



/** Polling fallback factor. */
const POLL_INTERVAL_MS = 2_000;


/**
 * Subscribe to a run's batch progress. Prefers SSE; falls back to polling.
 *
 * The hook always returns the *latest* ``AiBatchProgress`` it has seen.
 * Consumers don't need to know whether the data came from SSE or polling.
 */
export function useAiBatchProgress(
  runId: string | null,
  args: { enabled?: boolean } = {},
) {
  const { enabled = true } = args;
  const { key: scopeKey, ready: scopeReady, capture } = useMutationScope();
  const active = enabled && runId != null && scopeReady;
  const qc = useQueryClient();
  const [sseAvailable, setSseAvailable] = useState<SSEAvailable>(null);

  // Initial fetch + polling fallback. ``refetchInterval`` is suspended
  // (false) while SSE is healthy — when the stream succeeds for the
  // first time we flip ``sseAvailable=true`` and stop polling.
  const query = useQuery<AiBatchProgress | null>({
    queryKey: ['ai-batch-progress', runId],
    queryFn: ({ signal }) => getRunAiFixProgress(runId as string, signal),
    enabled: active,
    refetchInterval: (qData) => {
      if (!active) return false;
      if (sseAvailable === true) return false;
      const data = qData.state.data;
      // ``null`` = backend 204 (run exists, no batch — idle). Stop, same as
      // a terminal status; don't poll a dead/idle endpoint forever.
      if (data === null) return false;
      if (data && isAiBatchTerminal(data)) return false;
      return POLL_INTERVAL_MS;
    },
  });

  // SSE subscription.
  useEffect(() => {
    if (!active) return;
    const isCurrent = capture();
    let disposed = false;
    setSseAvailable(null);
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      setSseAvailable(false);
      return;
    }
    const url = aiFixStreamUrl(runId as string);
    let es: EventSource | null = null;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch {
      setSseAvailable(false);
      return;
    }
    es.addEventListener('progress', (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as AiBatchProgress;
        if (disposed || !isCurrent() || parsed.run_id !== runId) return;
        qc.setQueryData(['ai-batch-progress', runId], parsed);
        setSseAvailable(true);
        if (isAiBatchTerminal(parsed)) es?.close();
      } catch {
        // Ignore malformed events; the polling fallback will catch up.
      }
    });
    es.addEventListener('end', () => {
      es?.close();
      if (!disposed && isCurrent()) setSseAvailable(false);
    });
    es.onerror = () => {
      // Server unavailable → fall back to polling.
      if (!disposed && isCurrent()) setSseAvailable(false);
      es?.close();
    };
    return () => {
      disposed = true; es?.close();
    };
  }, [active, runId, qc, scopeKey, capture]);

  useEffect(() => {
    if (!active || !query.data) return;
    void reconcileAiBatchTerminal(qc, { progress: query.data, scope: scopeKey, isCurrent: capture() });
  }, [active, query.data, qc, scopeKey, capture]);

  return query;
}


// ─── Trigger / cancel mutations ─────────────────────────────────────────────


export function useTriggerAiFixes(runId: string) {
  const qc = useQueryClient();
  const { key: scopeKey, capture } = useMutationScope();
  return useMutation({
    mutationFn: (body: AiTriggerBatchRequest = {}) => triggerRunAiFixes(runId, body),
    onMutate: () => ({ isCurrent: capture(), scope: scopeKey }),
    onSuccess: async (resp, _body, context) => {
      if (!context?.isCurrent()) return;
      qc.setQueryData(['ai-batch-progress', runId], resp.progress);
      if (resp.batch_id) qc.setQueryData(['ai-batch-progress', runId, resp.batch_id], resp.progress);
      // Only progress/history at enqueue. Cached fixes change on server completion.
      await invalidateAiBatchSurfaces(qc, runId);
      await reconcileAiBatchTerminal(qc, { progress: resp.progress, scope: context.scope, isCurrent: context.isCurrent });
    },
  });
}


export function useCancelAiFixes(runId: string) {
  const qc = useQueryClient();
  const { key: scopeKey, capture } = useMutationScope();
  return useMutation({
    mutationFn: () => cancelRunAiFixes(runId),
    onMutate: () => ({ isCurrent: capture(), scope: scopeKey }),
    onSuccess: async (_resp, _variables, context) => {
      if (!context) return;
      await invalidateAiBatchCancellation(qc, { runId, batchId: qc.getQueryData<AiBatchProgress>(['ai-batch-progress', runId])?.batch_id ?? null, scope: context.scope, isCurrent: context.isCurrent });
    },
  });
}


export function useRunAiFixList(
  runId: string | null,
  args: { enabled?: boolean } = {},
) {
  const { enabled = true } = args;
  return useQuery<AiFindingFixListResponse>({
    queryKey: ['ai-fix-list', runId],
    queryFn: ({ signal }) => listRunAiFixes(runId as string, signal),
    enabled: enabled && runId != null,
  });
}


// ─── Multi-batch + scope-aware (Phase 4) ─────────────────────────────────────


/**
 * Scope-aware pre-flight estimate. Debounced internally so a user
 * fiddling with filter chips doesn't fire a request per keystroke.
 *
 * The query key includes a stable hash of the scope so two equivalent
 * scopes (e.g. severities=[CRITICAL,HIGH] vs [HIGH,CRITICAL]) share a
 * cache entry.
 */
export function useScopedRunBatchEstimate(
  runId: string | null,
  scope: AiFixGenerationScope | null,
  args: { enabled?: boolean; debounceMs?: number } = {},
) {
  const { enabled = true, debounceMs = 300 } = args;
  const [debouncedScope, setDebouncedScope] = useState(scope);
  const scopeKey = scopeCacheKey(scope);

  // Re-debounce only when the scope's stable hash changes — this stops
  // a parent re-render with an equivalent (but new-reference) scope
  // from re-triggering the timer.
  useEffect(() => {
    const handle = setTimeout(() => setDebouncedScope(scope), debounceMs);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scopeKey captures scope identity
  }, [scopeKey, debounceMs]);

  const debouncedKey = scopeCacheKey(debouncedScope);

  return useQuery<AiScopedEstimateResponse>({
    queryKey: ['ai', 'run-batch-estimate', runId, debouncedKey],
    queryFn: ({ signal }) =>
      estimateRunAiFixesScoped(runId as string, debouncedScope, signal),
    enabled: enabled && runId != null,
    staleTime: 30_000,
  });
}


/**
 * Trigger generation with an optional scope. Returns the new
 * ``batch_id`` in ``onSuccess``; consumers register that with the
 * global progress provider so the banner picks it up.
 */
export function useTriggerScopedAiFixes(runId: string) {
  const qc = useQueryClient();
  const { key: scopeKey, capture } = useMutationScope();
  return useMutation({
    mutationFn: (body: AiTriggerBatchRequest = {}) => triggerRunAiFixes(runId, body),
    onMutate: () => ({ isCurrent: capture(), scope: scopeKey }),
    onSuccess: async (resp, _body, context) => {
      if (!context?.isCurrent()) return;
      qc.setQueryData(['ai-batch-progress', runId], resp.progress);
      if (resp.batch_id) qc.setQueryData(['ai-batch-progress', runId, resp.batch_id], resp.progress);
      // Only progress/history at enqueue. Cached fixes change on server completion.
      await invalidateAiBatchSurfaces(qc, runId);
      await reconcileAiBatchTerminal(qc, { progress: resp.progress, scope: context.scope, isCurrent: context.isCurrent });
    },
  });
}


/** List every batch (active + historical) for a run. */
export function useRunAiBatches(
  runId: string | null,
  args: { enabled?: boolean; refetchIntervalMs?: number } = {},
) {
  const { enabled = true, refetchIntervalMs } = args;
  return useQuery<AiBatchListResponse>({
    queryKey: ['ai-batch-list', runId],
    queryFn: ({ signal }) => listRunAiBatches(runId as string, signal),
    enabled: enabled && runId != null,
    refetchInterval: refetchIntervalMs ?? false,
  });
}


/** Cancel one specific batch. */
export function useCancelAiBatch(runId: string) {
  const qc = useQueryClient();
  const { key: scopeKey, capture } = useMutationScope();
  return useMutation({
    mutationFn: (batchId: string) => cancelRunAiBatch(runId, batchId),
    onMutate: () => ({ isCurrent: capture(), scope: scopeKey }),
    onSuccess: async (_resp, batchId, context) => {
      if (!context) return;
      await invalidateAiBatchCancellation(qc, { runId, batchId: batchId, scope: context.scope, isCurrent: context.isCurrent });
    },
  });
}


// ─── Settings ───────────────────────────────────────────────────────────────


export interface AiSettingsState {
  providers: AiProviderInfo[] | undefined;
  pricing: AiPricingEntry[] | undefined;
  usage: AiUsageSummary | undefined;
  isLoading: boolean;
  isError: boolean;
}


export function useAiSettings(args: { enabled?: boolean } = {}): AiSettingsState {
  const { enabled = true } = args;
  const providers = useQuery({
    queryKey: ['ai-settings', 'providers'],
    queryFn: ({ signal }) => listAiProviders(signal),
    enabled,
    staleTime: 60_000,
  });
  const pricing = useQuery({
    queryKey: ['ai-settings', 'pricing'],
    queryFn: ({ signal }) => listAiPricing(signal),
    enabled,
    staleTime: 60 * 60_000, // pricing changes quarterly
  });
  const usage = useQuery({
    queryKey: ['ai-settings', 'usage'],
    queryFn: ({ signal }) => getAiUsageSummary(signal),
    enabled,
    refetchInterval: 30_000, // dashboard freshness
  });

  return {
    providers: providers.data,
    pricing: pricing.data,
    usage: usage.data,
    isLoading: providers.isLoading || pricing.isLoading || usage.isLoading,
    isError: providers.isError || pricing.isError || usage.isError,
  };
}


// ─── Cache helpers ──────────────────────────────────────────────────────────


/** Used after a regenerate or a cancelled batch — drops every AI fix entry
 *  for the active session. */
export function invalidateAllAiFixes(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['ai-fix'] });
  qc.invalidateQueries({ queryKey: ['ai-fix-list'] });
  qc.invalidateQueries({ queryKey: ['ai-batch-progress'] });
}
