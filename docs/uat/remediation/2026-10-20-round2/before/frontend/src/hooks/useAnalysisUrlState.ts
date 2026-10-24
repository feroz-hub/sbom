'use client';

import { useCallback, useMemo } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { canonicalRunStatus } from '@/lib/analysisRunStatusLabels';

export type AnalysisHubTab = 'runs' | 'consolidated' | 'vulnerabilities';

const KEYS = ['project', 'product', 'sbom', 'status', 'severity', 'tab'] as const;

export function useAnalysisUrlState() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const projectFilter = searchParams.get('project') ?? '';
  const productFilter = searchParams.get('product') ?? '';
  const sbomFilter = searchParams.get('sbom') ?? '';
  const rawStatusFilter = searchParams.get('status') ?? '';
  const statusFilter = rawStatusFilter ? canonicalRunStatus(rawStatusFilter) : '';
  const rawTab = searchParams.get('tab');
  const hubTab: AnalysisHubTab =
    rawTab === 'consolidated' ? 'consolidated' : rawTab === 'vulnerabilities' ? 'vulnerabilities' : 'runs';
  // Lowercase canonical severity bucket, or '' for "all severities". The URL is
  // user-editable, so an unrecognised value degrades to unfiltered rather than
  // seeding a filter that matches nothing.
  const rawSeverity = (searchParams.get('severity') ?? '').trim().toLowerCase();
  const severityFilter = ['critical', 'high', 'medium', 'low', 'unknown'].includes(rawSeverity)
    ? rawSeverity
    : '';

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

  // Deliberately independent of the project filter: selecting a product
  // never clears or narrows the project selection, and vice versa. The two
  // AND together on the server.
  const setProductFilter = useCallback(
    (value: string) => {
      replaceSearchParams((p) => {
        if (value) p.set('product', value);
        else p.delete('product');
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
        if (value) p.set('status', canonicalRunStatus(value));
        else p.delete('status');
      });
    },
    [replaceSearchParams],
  );

  const setSeverityFilter = useCallback(
    (value: string) => {
      replaceSearchParams((p) => {
        if (value) p.set('severity', value.toLowerCase());
        else p.delete('severity');
      });
    },
    [replaceSearchParams],
  );

  const setHubTab = useCallback(
    (tab: AnalysisHubTab) => {
      replaceSearchParams((p) => {
        if (tab === 'runs') p.delete('tab');
        else p.set('tab', tab);
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
    productFilter,
    sbomFilter,
    statusFilter,
    severityFilter,
    hubTab,
    setProjectFilter,
    setProductFilter,
    setSbomFilter,
    setSeverityFilter,
    setStatusFilter,
    setHubTab,
    clearFilters,
  };
}
