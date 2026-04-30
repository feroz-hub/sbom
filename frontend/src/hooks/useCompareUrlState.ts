'use client';

import { useCallback, useMemo } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import type {
  CompareTab,
  CompareUrlState,
  FindingChangeKind,
} from '@/types/compare';

/**
 * URL is the source of truth for the compare page (ADR-0008 §4).
 *
 * Push-vs-replace semantics (ADR-0008 §8):
 *   - `setRuns` and `setTab` PUSH a history entry — these are navigation events
 *     a user might want to back-button to.
 *   - All filter mutations REPLACE the current entry — the back button takes
 *     the user out of the page rather than through every chip toggle.
 */

const DEFAULT_CHANGE_KINDS: ReadonlySet<FindingChangeKind> = new Set([
  'added',
  'resolved',
  'severity_changed',
]);

const VALID_TABS: ReadonlySet<CompareTab> = new Set([
  'findings',
  'components',
  'delta',
]);

const VALID_CHANGE_KINDS: ReadonlySet<FindingChangeKind> = new Set([
  'added',
  'resolved',
  'severity_changed',
  'unchanged',
]);

const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
]);

function parseRunId(value: string | null): number | null {
  if (!value) return null;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function parseTab(raw: string | null): CompareTab {
  return raw && VALID_TABS.has(raw as CompareTab) ? (raw as CompareTab) : 'findings';
}

function parseSet<T extends string>(
  raw: string | null,
  valid: ReadonlySet<string>,
  fallback: ReadonlySet<T>,
): Set<T> {
  if (raw === null) return new Set(fallback);
  if (raw === '') return new Set();
  const parts = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => valid.has(s));
  return new Set(parts as T[]);
}

function parseBool(raw: string | null): boolean {
  return raw === 'true' || raw === '1';
}

export function useCompareUrlState(): CompareUrlState & {
  setRuns: (runA: number | null, runB: number | null) => void;
  swap: () => void;
  setTab: (tab: CompareTab) => void;
  setChangeKinds: (kinds: Set<FindingChangeKind>) => void;
  toggleChangeKind: (kind: FindingChangeKind) => void;
  setSeverities: (severities: Set<string>) => void;
  toggleSeverity: (severity: string) => void;
  setKevOnly: (value: boolean) => void;
  setFixAvailable: (value: boolean) => void;
  setShowUnchanged: (value: boolean) => void;
  setQ: (q: string) => void;
  shareUrl: () => string;
  showSharedFindings: () => void;
  clearAllFilters: () => void;
} {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const queryString = useMemo(() => searchParams.toString(), [searchParams]);

  const runA = parseRunId(searchParams.get('run_a'));
  const runB = parseRunId(searchParams.get('run_b'));
  const tab = parseTab(searchParams.get('tab'));
  const changeKinds = parseSet<FindingChangeKind>(
    searchParams.get('change'),
    VALID_CHANGE_KINDS,
    DEFAULT_CHANGE_KINDS,
  );
  const severities = parseSet<string>(
    searchParams.get('severity'),
    VALID_SEVERITIES,
    new Set(VALID_SEVERITIES),
  );
  const kevOnly = parseBool(searchParams.get('kev_only'));
  const fixAvailable = parseBool(searchParams.get('fix_available'));
  const showUnchanged = parseBool(searchParams.get('show_unchanged'));
  const q = searchParams.get('q') ?? '';

  const writeParams = useCallback(
    (mutate: (p: URLSearchParams) => void, mode: 'push' | 'replace' = 'replace') => {
      const p = new URLSearchParams(queryString);
      mutate(p);
      const qs = p.toString();
      const next = qs ? `${pathname}?${qs}` : pathname;
      if (mode === 'push') router.push(next, { scroll: false });
      else router.replace(next, { scroll: false });
    },
    [pathname, queryString, router],
  );

  const setRuns = useCallback(
    (a: number | null, b: number | null) =>
      writeParams((p) => {
        if (a) p.set('run_a', String(a));
        else p.delete('run_a');
        if (b) p.set('run_b', String(b));
        else p.delete('run_b');
      }, 'push'),
    [writeParams],
  );

  const swap = useCallback(
    () => setRuns(runB, runA),
    [runA, runB, setRuns],
  );

  const setTab = useCallback(
    (next: CompareTab) =>
      writeParams((p) => {
        if (next === 'findings') p.delete('tab');
        else p.set('tab', next);
      }, 'push'),
    [writeParams],
  );

  const setChangeKinds = useCallback(
    (kinds: Set<FindingChangeKind>) =>
      writeParams((p) => {
        const sorted = Array.from(kinds).sort();
        const isDefault =
          sorted.length === DEFAULT_CHANGE_KINDS.size &&
          sorted.every((k) => DEFAULT_CHANGE_KINDS.has(k));
        if (isDefault) p.delete('change');
        else p.set('change', sorted.join(','));
      }),
    [writeParams],
  );

  const toggleChangeKind = useCallback(
    (kind: FindingChangeKind) => {
      const next = new Set(changeKinds);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      setChangeKinds(next);
    },
    [changeKinds, setChangeKinds],
  );

  const setSeverities = useCallback(
    (next: Set<string>) =>
      writeParams((p) => {
        const sorted = Array.from(next).sort();
        const isDefault = sorted.length === VALID_SEVERITIES.size;
        if (isDefault) p.delete('severity');
        else p.set('severity', sorted.join(','));
      }),
    [writeParams],
  );

  const toggleSeverity = useCallback(
    (sev: string) => {
      const next = new Set(severities);
      const lower = sev.toLowerCase();
      if (next.has(lower)) next.delete(lower);
      else next.add(lower);
      setSeverities(next);
    },
    [severities, setSeverities],
  );

  const makeBoolSetter = (key: string) =>
    (value: boolean) =>
      writeParams((p) => {
        if (value) p.set(key, 'true');
        else p.delete(key);
      });

  const setKevOnly = useCallback(makeBoolSetter('kev_only'), [writeParams]);
  const setFixAvailable = useCallback(makeBoolSetter('fix_available'), [writeParams]);
  const setShowUnchanged = useCallback(makeBoolSetter('show_unchanged'), [writeParams]);

  const setQ = useCallback(
    (next: string) =>
      writeParams((p) => {
        if (next) p.set('q', next);
        else p.delete('q');
      }),
    [writeParams],
  );

  const shareUrl = useCallback(() => {
    if (typeof window === 'undefined') return '';
    return window.location.href;
  }, []);

  // Composite navigation: Identical-runs CTA jumps to Findings tab with
  // ?show_unchanged=true so the user can browse the shared set.
  const showSharedFindings = useCallback(
    () =>
      writeParams((p) => {
        p.delete('tab'); // findings is the default — omit
        p.set('show_unchanged', 'true');
      }, 'push'),
    [writeParams],
  );

  // Reset all filter state to default. Used by FilterChipsAdaptive's
  // "Clear all" button. Run selection (run_a/run_b) and tab choice are
  // preserved.
  const clearAllFilters = useCallback(
    () =>
      writeParams((p) => {
        p.delete('change');
        p.delete('severity');
        p.delete('kev_only');
        p.delete('fix_available');
        p.delete('show_unchanged');
        p.delete('q');
      }),
    [writeParams],
  );

  return {
    runA,
    runB,
    tab,
    changeKinds,
    severities,
    kevOnly,
    fixAvailable,
    showUnchanged,
    q,
    setRuns,
    swap,
    setTab,
    setChangeKinds,
    toggleChangeKind,
    setSeverities,
    toggleSeverity,
    setKevOnly,
    setFixAvailable,
    setShowUnchanged,
    setQ,
    shareUrl,
    showSharedFindings,
    clearAllFilters,
  };
}
