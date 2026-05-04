/**
 * Hooks for the AI fix surface.
 *
 *   * ``useAiFix`` — fetch (or generate) the bundle for one finding, plus
 *     a ``regenerate`` mutation. Keys the cache on (findingId, provider)
 *     so switching providers in Settings invalidates per-finding cache
 *     entries naturally.
 *
 *   * ``useAiBatchProgress`` — subscribe to a run's batch state. Tries
 *     SSE first (live updates with no polling spend); falls back to
 *     polling every 2s when ``EventSource`` is unavailable or the
 *     stream errors.
 *
 *   * ``useAiSettings`` — providers + pricing + usage summary, joined
 *     into one shape the Settings page consumes.
 */

import { useEffect, useState } from 'react';
import {
  type QueryClient,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import {
  aiFixStreamUrl,
  cancelRunAiFixes,
  getAiUsageSummary,
  getFindingAiFix,
  getRunAiFixProgress,
  listAiPricing,
  listAiProviders,
  listRunAiFixes,
  regenerateFindingAiFix,
  triggerRunAiFixes,
} from '@/lib/api';
import type {
  AiBatchProgress,
  AiFindingFixEnvelope,
  AiFindingFixListResponse,
  AiPricingEntry,
  AiProviderInfo,
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

  const query = useQuery<AiFindingFixEnvelope>({
    queryKey: aiFixQueryKey(findingId ?? -1, providerName),
    queryFn: ({ signal }) =>
      getFindingAiFix(findingId as number, { providerName }, signal),
    enabled: enabled && findingId != null,
    // Cached fix bundles have a TTL of 7-30 days at the server; on the
    // client we keep them for 5 minutes before refetching so a re-open
    // of the modal feels instant.
    staleTime: 5 * 60_000,
  });

  const regenerate = useMutation<AiFindingFixEnvelope, Error, void>({
    mutationFn: () =>
      regenerateFindingAiFix(findingId as number, { providerName }),
    onSuccess: (data) => {
      qc.setQueryData(aiFixQueryKey(findingId ?? -1, providerName), data);
    },
  });

  return { ...query, regenerate };
}


// ─── Batch progress ─────────────────────────────────────────────────────────


type SSEAvailable = boolean | null;


function isTerminal(status: AiBatchProgress['status']): boolean {
  return status === 'complete' || status === 'failed' || status === 'cancelled';
}


/** Polling fallback factor. */
const POLL_INTERVAL_MS = 2_000;


/**
 * Subscribe to a run's batch progress. Prefers SSE; falls back to polling.
 *
 * The hook always returns the *latest* ``AiBatchProgress`` it has seen.
 * Consumers don't need to know whether the data came from SSE or polling.
 */
export function useAiBatchProgress(
  runId: number | null,
  args: { enabled?: boolean } = {},
) {
  const { enabled = true } = args;
  const active = enabled && runId != null;
  const qc = useQueryClient();
  const [sseAvailable, setSseAvailable] = useState<SSEAvailable>(null);

  // Initial fetch + polling fallback. ``refetchInterval`` is suspended
  // (false) while SSE is healthy — when the stream succeeds for the
  // first time we flip ``sseAvailable=true`` and stop polling.
  const query = useQuery<AiBatchProgress>({
    queryKey: ['ai-batch-progress', runId],
    queryFn: ({ signal }) => getRunAiFixProgress(runId as number, signal),
    enabled: active,
    refetchInterval: (qData) => {
      if (!active) return false;
      if (sseAvailable === true) return false;
      const data = qData.state.data;
      if (data && isTerminal(data.status)) return false;
      return POLL_INTERVAL_MS;
    },
  });

  // SSE subscription.
  useEffect(() => {
    if (!active) return;
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      setSseAvailable(false);
      return;
    }
    const url = aiFixStreamUrl(runId as number);
    let es: EventSource | null = null;
    try {
      es = new EventSource(url, { withCredentials: false });
    } catch {
      setSseAvailable(false);
      return;
    }
    es.addEventListener('progress', (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as AiBatchProgress;
        qc.setQueryData(['ai-batch-progress', runId], parsed);
        setSseAvailable(true);
      } catch {
        // Ignore malformed events; the polling fallback will catch up.
      }
    });
    es.addEventListener('end', () => {
      es?.close();
    });
    es.onerror = () => {
      // Server unavailable → fall back to polling.
      setSseAvailable(false);
      es?.close();
    };
    return () => {
      es?.close();
    };
  }, [active, runId, qc]);

  return query;
}


// ─── Trigger / cancel mutations ─────────────────────────────────────────────


export function useTriggerAiFixes(runId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AiTriggerBatchRequest = {}) => triggerRunAiFixes(runId, body),
    onSuccess: (resp) => {
      qc.setQueryData(['ai-batch-progress', runId], resp.progress);
      // The list of cached fixes will change as the batch completes —
      // invalidate so the run-detail table re-fetches when the user
      // opens it next.
      qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] });
    },
  });
}


export function useCancelAiFixes(runId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => cancelRunAiFixes(runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-batch-progress', runId] });
    },
  });
}


export function useRunAiFixList(
  runId: number | null,
  args: { enabled?: boolean } = {},
) {
  const { enabled = true } = args;
  return useQuery<AiFindingFixListResponse>({
    queryKey: ['ai-fix-list', runId],
    queryFn: ({ signal }) => listRunAiFixes(runId as number, signal),
    enabled: enabled && runId != null,
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
