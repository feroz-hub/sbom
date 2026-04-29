'use client';

import { useCallback, useMemo } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

export type AnalysisHubTab = 'runs' | 'consolidated';

const KEYS = ['project', 'sbom', 'status', 'tab'] as const;

export function useAnalysisUrlState() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const projectFilter = searchParams.get('project') ?? '';
  const sbomFilter = searchParams.get('sbom') ?? '';
  const statusFilter = searchParams.get('status') ?? '';
  const hubTab: AnalysisHubTab =
    searchParams.get('tab') === 'consolidated' ? 'consolidated' : 'runs';

  const queryString = useMemo(() => searchParams.toString(), [searchParams]);

  const replaceSearchParams = useCallback(
    (mutate: (p: URLSearchParams) => void) => {
      const p = new URLSearchParams(queryString);
      mutate(p);
      const qs = p.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [pathname, queryString, router],
  );

  const setProjectFilter = useCallback(
    (value: string) => {
      replaceSearchParams((p) => {
        if (value) p.set('project', value);
        else p.delete('project');
      });
    },
    [replaceSearchParams],
  );

  const setSbomFilter = useCallback(
    (value: string) => {
      replaceSearchParams((p) => {
        if (value) p.set('sbom', value);
        else p.delete('sbom');
      });
    },
    [replaceSearchParams],
  );

  const setStatusFilter = useCallback(
    (value: string) => {
      replaceSearchParams((p) => {
        if (value) p.set('status', value);
        else p.delete('status');
      });
    },
    [replaceSearchParams],
  );

  const setHubTab = useCallback(
    (tab: AnalysisHubTab) => {
      replaceSearchParams((p) => {
        if (tab === 'consolidated') p.set('tab', 'consolidated');
        else p.delete('tab');
      });
    },
    [replaceSearchParams],
  );

  const clearFilters = useCallback(() => {
    replaceSearchParams((p) => {
      for (const k of KEYS) {
        if (k !== 'tab') p.delete(k);
      }
    });
  }, [replaceSearchParams]);

  return {
    projectFilter,
    sbomFilter,
    statusFilter,
    hubTab,
    setProjectFilter,
    setSbomFilter,
    setStatusFilter,
    setHubTab,
    clearFilters,
  };
}
