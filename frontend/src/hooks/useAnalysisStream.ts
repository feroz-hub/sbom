'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { BASE_URL, getRun } from '@/lib/api';
import { invalidateAnalysisCompletion } from '@/lib/queryInvalidation';
import { reconcileAnalysisTerminal, isTerminalAnalysis } from '@/lib/analysisSync';
import { addPendingAnalysis, removePendingAnalysis } from '@/lib/pendingAnalysis';
import { useAnalysisScope } from './useAnalysisScope';
import { getActiveTenantId } from '@/lib/auth';

// ─── Types ───────────────────────────────────────────────────────────────────

export type SourceStatus = 'pending' | 'running' | 'complete' | 'error' | 'skipped';

export interface SourceProgress {
  name: string;
  status: SourceStatus;
  findings: number;
  errors: number;
  elapsedMs: number;
  sourceMs: number;
  error?: string;
}

export interface AnalysisStreamState {
  phase: 'idle' | 'connecting' | 'parsing' | 'running' | 'done' | 'error';
  components: number;
  sources: Record<string, SourceProgress>;
  elapsedMs: number;
  runId: string | null;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  } | null;
  error: string | null;
}

export interface StartAnalysisOptions {
  sources?: string[];
  nvdApiKey?: string;
  githubToken?: string;
}

const INITIAL_STATE: AnalysisStreamState = {
  phase: 'idle',
  components: 0,
  sources: {},
  elapsedMs: 0,
  runId: null,
  summary: null,
  error: null,
};

// ─── Hook ────────────────────────────────────────────────────────────────────

export function useAnalysisStream(sbomId: (string | number)) {
  const [state, setState] = useState<AnalysisStreamState>(INITIAL_STATE);
  const queryClient = useQueryClient();
  const scope = useAnalysisScope();
  const runIdRef = useRef<string | null>(null);

  // Elapsed wall-clock timer, updated every 500ms
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startTimeRef = useRef<number>(0);
  const abortRef = useRef<AbortController | null>(null);
  const runningAnalysisRef = useRef<Set<string | number>>(new Set());

  const stopTimer = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const startTimer = useCallback(() => {
    stopTimer();
    startTimeRef.current = Date.now();
    timerRef.current = setInterval(() => {
      setState((prev) => ({
        ...prev,
        elapsedMs: Date.now() - startTimeRef.current,
      }));
    }, 500);
  }, [stopTimer]);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    stopTimer();
    setState((prev) => ({
      ...prev,
      phase: prev.phase === 'done' ? 'done' : 'idle',
    }));
  }, [stopTimer]);

  useEffect(() => () => { abortRef.current?.abort(); stopTimer(); }, [scope.key, scope.ready, stopTimer]);

  const startAnalysis = useCallback(
    async (options: StartAnalysisOptions = {}) => {
      if (!sbomId || !scope.ready || runningAnalysisRef.current.has(sbomId)) return;
      const isCurrent = scope.capture();

      // Analysis is tenant-scoped on the backend. Without an active tenant the
      // request would go out unscoped and come back 403, so fail inline before
      // anything is sent, started, or timed.
      const tenantId = getActiveTenantId();
      if (!tenantId) {
        setState({
          ...INITIAL_STATE,
          phase: 'error',
          error: 'Select a tenant before running analysis.',
        });
        return;
      }

      addPendingAnalysis(sbomId, `SBOM #${sbomId}`, scope.key);
      runIdRef.current = null;
      runningAnalysisRef.current.add(sbomId);
      const clearPending = () => {
        runningAnalysisRef.current.delete(sbomId);
      };

      const controller = new AbortController();
      abortRef.current = controller;

      // Omission delegates to the server's configured provider policy.
      const initialSources = options.sources?.map((s) => s.toUpperCase());

      // Seed source entries so the UI can show all sources immediately
      const sourcesMap: Record<string, SourceProgress> = {};
      for (const name of initialSources ?? []) {
        sourcesMap[name] = { name, status: 'pending', findings: 0, errors: 0, elapsedMs: 0, sourceMs: 0 };
      }

      setState({
        phase: 'connecting',
        components: 0,
        sources: sourcesMap,
        elapsedMs: 0,
        runId: null,
        summary: null,
        error: null,
      });

      startTimer();

      const url = `${BASE_URL}/api/sboms/${sbomId}/analyze/stream`;
      const randomId =
        globalThis.crypto?.randomUUID?.() ??
        `${Date.now()}-${Math.random().toString(36).slice(2)}`;

      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': `analysis-sbom-${sbomId}-${randomId}`,
            'X-Tenant-ID': tenantId,
          },
          body: JSON.stringify({
            sources: initialSources,
            nvd_api_key: options.nvdApiKey ?? null,
            github_token: options.githubToken ?? null,
          }),
          signal: controller.signal,
        });
      } catch (err: unknown) {
        // Release the local start reservation even when auth context retired.
        // The guard still prevents old requests from writing state or caches.
        clearPending();
        if (!isCurrent()) return;
        stopTimer();
        if ((err as Error)?.name === 'AbortError') return;
        setState((prev) => ({
          ...prev,
          phase: 'error',
          error: (err as Error)?.message ?? 'Connection failed',
        }));
        return;
      }

      if (!isCurrent()) { clearPending(); return; }
      if (!response.ok) {
        stopTimer();
        clearPending();
        let msg = `HTTP ${response.status}`;
        try {
          const body = await response.json();
          msg = body?.detail ?? msg;
        } catch { /* ignore */ }
        setState((prev) => ({ ...prev, phase: 'error', error: msg }));
        return;
      }

      // Parse the SSE stream from the response body
      const reader = response.body?.getReader();
      if (!reader) {
        stopTimer();
        clearPending();
        setState((prev) => ({ ...prev, phase: 'error', error: 'No response body' }));
        return;
      }

      const decoder = new TextDecoder();
      let buffer = '';

      const parseEvents = (chunk: string) => {
        buffer += chunk;
        const parts = buffer.split('\n\n');
        buffer = parts.pop() ?? '';

        for (const part of parts) {
          const lines = part.trim().split('\n');
          let eventType = 'message';
          let dataStr = '';
          for (const line of lines) {
            if (line.startsWith('event: ')) eventType = line.slice(7).trim();
            else if (line.startsWith('data: ')) dataStr = line.slice(6).trim();
          }
          if (!dataStr) continue;

          let data: Record<string, unknown>;
          try {
            data = JSON.parse(dataStr);
          } catch {
            continue;
          }

          handleEvent(eventType, data);
        }
      };

      const handleEvent = (eventType: string, data: Record<string, unknown>) => {
        if (!isCurrent()) return;
        if (typeof data.runId === 'string') {
          runIdRef.current = data.runId;
          addPendingAnalysis(sbomId, `SBOM #${sbomId}`, scope.key, data.runId);
        }
        if (eventType === 'progress') {
          const phase = data.phase as string | undefined;
          const sourceName = data.source as string | undefined;

          if (phase === 'started') {
            setState((prev) => ({ ...prev, phase: 'parsing' }));
          } else if (phase === 'parsed') {
            setState((prev) => ({
              ...prev,
              phase: 'running',
              components: (data.components as number) ?? prev.components,
            }));
          } else if (sourceName) {
            const status = data.status as SourceStatus;
            setState((prev) => ({
              ...prev,
              sources: {
                ...prev.sources,
                [sourceName]: {
                  name: sourceName,
                  status,
                  findings: (data.findings as number) ?? prev.sources[sourceName]?.findings ?? 0,
                  errors: (data.errors as number) ?? prev.sources[sourceName]?.errors ?? 0,
                  elapsedMs: (data.elapsed_ms as number) ?? 0,
                  sourceMs: (data.source_ms as number) ?? 0,
                  error: data.error as string | undefined,
                },
              },
            }));
          }
        } else if (eventType === 'complete') {
          stopTimer();
          void reconcileAnalysisTerminal(queryClient, { scope: scope.key, runId: String(data.runId), sbomId,
            status: String(data.status ?? ''), isCurrent });
          removePendingAnalysis(sbomId, scope.key);
          setState((prev) => ({
            ...prev,
            phase: 'done',
            runId: data.runId as string,
            elapsedMs: (data.duration_ms as number) ?? prev.elapsedMs,
            summary: {
              total: (data.total as number) ?? 0,
              critical: (data.critical as number) ?? 0,
              high: (data.high as number) ?? 0,
              medium: (data.medium as number) ?? 0,
              low: (data.low as number) ?? 0,
              unknown: (data.unknown as number) ?? 0,
            },
          }));
        } else if (eventType === 'error') {
          stopTimer();
          const runId = runIdRef.current;
          if (runId) void getRun(runId).then(async run => {
            if (!isCurrent()) return;
            await reconcileAnalysisTerminal(queryClient, { scope: scope.key, runId, sbomId, status: run.run_status, isCurrent });
            if (isCurrent() && isTerminalAnalysis(run.run_status)) removePendingAnalysis(sbomId, scope.key);
          }).catch(() => { /* Recovery retries authoritative state; no guessed terminal status. */ });
          else void invalidateAnalysisCompletion(queryClient, { sbomId });
          setState((prev) => ({
            ...prev,
            phase: 'error',
            error: (data.message as string) ?? 'Unknown error',
          }));
        }
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          parseEvents(decoder.decode(value, { stream: true }));
        }
      } catch (err: unknown) {
        if (isCurrent() && (err as Error)?.name !== 'AbortError') {
          stopTimer();
          setState((prev) => ({
            ...prev,
            phase: 'error',
            error: (err as Error)?.message ?? 'Stream read error',
          }));
        }
      } finally {
        reader.releaseLock();
        if (isCurrent()) stopTimer();
        clearPending();
      }
    },
    [queryClient, sbomId, startTimer, stopTimer, scope],
  );

  const reset = useCallback(() => {
    cancel();
    setState(INITIAL_STATE);
  }, [cancel]);

  return { state, startAnalysis, cancel, reset };
}
