'use client';

import { useState, useRef, useCallback } from 'react';
import { BASE_URL } from '@/lib/api';

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
  runId: number | null;
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

export function useAnalysisStream(sbomId: number) {
  const [state, setState] = useState<AnalysisStreamState>(INITIAL_STATE);

  // Elapsed wall-clock timer, updated every 500ms
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startTimeRef = useRef<number>(0);
  const abortRef = useRef<AbortController | null>(null);

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

  const startAnalysis = useCallback(
    async (options: StartAnalysisOptions = {}) => {
      // Cancel any running stream
      abortRef.current?.abort();

      const controller = new AbortController();
      abortRef.current = controller;

      const initialSources = (options.sources ?? ['NVD', 'OSV', 'GITHUB', 'VULNDB']).map((s) => s.toUpperCase());

      // Seed source entries so the UI can show all sources immediately
      const sourcesMap: Record<string, SourceProgress> = {};
      for (const name of initialSources) {
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

      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sources: initialSources,
            nvd_api_key: options.nvdApiKey ?? null,
            github_token: options.githubToken ?? null,
          }),
          signal: controller.signal,
        });
      } catch (err: unknown) {
        stopTimer();
        if ((err as Error)?.name === 'AbortError') return;
        setState((prev) => ({
          ...prev,
          phase: 'error',
          error: (err as Error)?.message ?? 'Connection failed',
        }));
        return;
      }

      if (!response.ok) {
        stopTimer();
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
          setState((prev) => ({
            ...prev,
            phase: 'done',
            runId: data.runId as number,
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
        if ((err as Error)?.name !== 'AbortError') {
          stopTimer();
          setState((prev) => ({
            ...prev,
            phase: 'error',
            error: (err as Error)?.message ?? 'Stream read error',
          }));
        }
      } finally {
        reader.releaseLock();
        stopTimer();
      }
    },
    [sbomId, startTimer, stopTimer],
  );

  const reset = useCallback(() => {
    cancel();
    setState(INITIAL_STATE);
  }, [cancel]);

  return { state, startAnalysis, cancel, reset };
}
