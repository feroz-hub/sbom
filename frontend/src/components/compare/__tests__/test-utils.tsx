/**
 * Compare-page test helpers.
 *
 *   * ``renderWithCompareProviders`` wraps the UI with QueryClient + Toast
 *     and a controllable ``next/navigation`` mock so URL-driven state can
 *     be exercised without a real router.
 *   * ``createNavigationMock`` returns a mock pair (router stub +
 *     searchParams) the test can read/mutate. Wire it via the test's
 *     ``vi.mock('next/navigation', ...)`` block.
 *   * Sample ``CompareResult`` fixture covers the happy path plus all
 *     change_kinds the table renders.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import { ToastProvider } from '@/hooks/useToast';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import type { CompareResult } from '@/types/compare';

export function newQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

export function Providers({
  client,
  children,
}: {
  client?: QueryClient;
  children: ReactNode;
}) {
  const qc = client ?? newQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider>
        <ToastProvider>{children}</ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export function renderWithCompareProviders(
  ui: ReactElement,
  opts?: RenderOptions & { client?: QueryClient },
) {
  const { client, ...rest } = opts ?? {};
  return render(ui, {
    wrapper: ({ children }) => <Providers client={client}>{children}</Providers>,
    ...rest,
  });
}

/**
 * Creates a controllable navigation mock surface. Test wires this into the
 * module mock so ``useRouter`` and ``useSearchParams`` return values that
 * the test can poke.
 */
export function createNavigationState(initialQuery = '') {
  const params = new URLSearchParams(initialQuery);
  const calls: Array<{ method: 'push' | 'replace'; href: string }> = [];

  const router = {
    push: (href: string) => {
      calls.push({ method: 'push', href });
      const q = href.includes('?') ? href.split('?')[1] : '';
      params.forEach((_, k) => params.delete(k));
      new URLSearchParams(q).forEach((v, k) => params.set(k, v));
    },
    replace: (href: string) => {
      calls.push({ method: 'replace', href });
      const q = href.includes('?') ? href.split('?')[1] : '';
      params.forEach((_, k) => params.delete(k));
      new URLSearchParams(q).forEach((v, k) => params.set(k, v));
    },
    back: () => calls.push({ method: 'push', href: 'BACK' }),
    forward: () => {},
    refresh: () => {},
    prefetch: () => Promise.resolve(),
  };

  return {
    router,
    params,
    pathname: () => '/analysis/compare',
    calls,
  };
}

// =============================================================================
// Sample CompareResult — covers added / resolved / severity_changed / unchanged
// for findings, plus added / removed / version_bumped for components.
// =============================================================================

export const SAMPLE_COMPARE_RESULT: CompareResult = {
  cache_key: 'a'.repeat(64),
  run_a: {
    id: 1,
    sbom_id: 100,
    sbom_name: 'sample-sbom',
    project_id: 200,
    project_name: 'Sample Project',
    run_status: 'FINDINGS',
    completed_on: '2026-04-15T12:00:00Z',
    started_on: '2026-04-15T11:50:00Z',
    total_findings: 4,
    total_components: 3,
  },
  run_b: {
    id: 2,
    sbom_id: 101,
    sbom_name: 'sample-sbom',
    project_id: 200,
    project_name: 'Sample Project',
    run_status: 'FINDINGS',
    completed_on: '2026-04-30T12:00:00Z',
    started_on: '2026-04-30T11:50:00Z',
    total_findings: 3,
    total_components: 4,
  },
  relationship: {
    same_project: true,
    same_sbom: false,
    days_between: 15.0,
    direction_warning: null,
  },
  posture: {
    kev_count_a: 2,
    kev_count_b: 1,
    kev_count_delta: -1,
    fix_available_pct_a: 50.0,
    fix_available_pct_b: 75.0,
    fix_available_pct_delta: 25.0,
    high_critical_count_a: 3,
    high_critical_count_b: 2,
    high_critical_count_delta: -1,
    findings_added_count: 1,
    findings_resolved_count: 2,
    findings_severity_changed_count: 1,
    findings_unchanged_count: 0,
    components_added_count: 1,
    components_removed_count: 0,
    components_version_bumped_count: 1,
    components_unchanged_count: 1,
    severity_distribution_a: { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0 },
    severity_distribution_b: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0 },
    top_resolutions: [],
    top_regressions: [],
  },
  findings: [
    {
      change_kind: 'resolved',
      vuln_id: 'CVE-2021-44832',
      severity_a: 'critical',
      severity_b: null,
      kev_current: true,
      epss_current: 0.97,
      epss_percentile_current: 0.99,
      component_name: 'log4j-core',
      component_version_a: '2.16.0',
      component_version_b: null,
      component_purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0',
      component_ecosystem: 'maven',
      fix_available: true,
      attribution: 'via upgrade log4j-core 2.16.0 → 2.17.1',
    },
    {
      change_kind: 'added',
      vuln_id: 'CVE-2024-12345',
      severity_a: null,
      severity_b: 'high',
      kev_current: false,
      epss_current: 0.05,
      epss_percentile_current: 0.55,
      component_name: 'pyyaml',
      component_version_a: null,
      component_version_b: '6.0.1',
      component_purl: 'pkg:pypi/pyyaml@6.0.1',
      component_ecosystem: 'PyPI',
      fix_available: true,
      attribution: 'via new dependency pyyaml@6.0.1',
    },
    {
      change_kind: 'severity_changed',
      vuln_id: 'CVE-2023-9999',
      severity_a: 'medium',
      severity_b: 'critical',
      kev_current: false,
      epss_current: null,
      epss_percentile_current: null,
      component_name: 'requests',
      component_version_a: '2.31.0',
      component_version_b: '2.31.0',
      component_purl: 'pkg:pypi/requests@2.31.0',
      component_ecosystem: 'PyPI',
      fix_available: false,
      attribution: null,
    },
    {
      change_kind: 'resolved',
      vuln_id: 'CVE-2021-45046',
      severity_a: 'critical',
      severity_b: null,
      kev_current: true,
      epss_current: 0.93,
      epss_percentile_current: 0.97,
      component_name: 'log4j-core',
      component_version_a: '2.16.0',
      component_version_b: null,
      component_purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0',
      component_ecosystem: 'maven',
      fix_available: true,
      attribution: 'via upgrade log4j-core 2.16.0 → 2.17.1',
    },
  ],
  components: [
    {
      change_kind: 'version_bumped',
      name: 'log4j-core',
      ecosystem: 'maven',
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1',
      version_a: '2.16.0',
      version_b: '2.17.1',
      license_a: null,
      license_b: null,
      hash_a: null,
      hash_b: null,
      findings_resolved: 2,
      findings_added: 0,
    },
    {
      change_kind: 'added',
      name: 'pyyaml',
      ecosystem: 'PyPI',
      purl: 'pkg:pypi/pyyaml@6.0.1',
      version_a: null,
      version_b: '6.0.1',
      license_a: null,
      license_b: null,
      hash_a: null,
      hash_b: null,
      findings_resolved: 0,
      findings_added: 1,
    },
    {
      change_kind: 'unchanged',
      name: 'requests',
      ecosystem: 'PyPI',
      purl: 'pkg:pypi/requests@2.31.0',
      version_a: '2.31.0',
      version_b: '2.31.0',
      license_a: null,
      license_b: null,
      hash_a: null,
      hash_b: null,
      findings_resolved: 0,
      findings_added: 0,
    },
  ],
  computed_at: '2026-04-30T12:30:00Z',
  schema_version: 1,
};
