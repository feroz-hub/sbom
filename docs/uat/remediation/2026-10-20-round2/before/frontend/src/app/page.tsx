'use client';

import { Suspense, useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { ClipboardCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Motion } from '@/components/ui/Motion';
import { HeroPostureCard } from '@/components/dashboard/HeroPostureCard/HeroPostureCard';
import { WhatsNewStrip } from '@/components/dashboard/WhatsNewStrip';
import { DashboardOperations, PortfolioHealth, SeverityBars } from '@/components/dashboard/PortfolioOverview';
import { CounterTiles } from '@/components/dashboard/CounterTiles';
import { LifecycleHealthTiles } from '@/components/dashboard/LifecycleHealthTiles';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { VulnerabilityAgePie } from '@/components/dashboard/VulnerabilityAgePie';
import { TrendExplorer } from '@/components/dashboard/TrendExplorer';
import { QuickActionsV2 } from '@/components/dashboard/QuickActionsV2/QuickActionsV2';
import { PortfolioTrend } from '@/components/dashboard/PortfolioTrend';
import { LifetimeStats } from '@/components/dashboard/LifetimeStats/LifetimeStats';
import { TopVulnerableSboms } from '@/components/dashboard/TopVulnerableSboms';
import { ActivityFeed } from '@/components/dashboard/ActivityFeed';
import { DashboardFilters } from '@/components/dashboard/DashboardFilters';
import { DashboardEmptyState } from '@/components/dashboard/DashboardEmptyState';
import { AiConfigBanner } from '@/components/dashboard/AiConfigBanner';
import { CopilotPanel } from '@/components/dashboard/advanced/CopilotPanel';
import { ForecastCard } from '@/components/dashboard/advanced/ForecastCard';
import { ExploitationOutlookCard } from '@/components/dashboard/advanced/ExploitationOutlookCard';
import { PortfolioRiskMap } from '@/components/dashboard/advanced/PortfolioRiskMap';
import { RiskMatrixCard } from '@/components/dashboard/advanced/RiskMatrixCard';
import { RemediationPanel } from '@/components/dashboard/advanced/RemediationPanel';
import {
  getDashboardSummary,
  getDashboardRuns,
  type DashboardFilterScope,
} from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { aggregateRuns, type SeverityKey } from '@/lib/topVulnerableRuns';
import { HIGH_EPSS_PERCENTILE } from '@/lib/findingFilters';
import { parseDashboardScope } from '@/lib/dashboardScopeUrl';

const DRILLABLE_SEVERITIES: readonly SeverityKey[] = [
  'critical',
  'high',
  'medium',
  'low',
];

/** Portfolio overview backed by the canonical dashboard summary.
 * Primary metrics and operations precede the retained advanced capabilities.
 * Scope, lifecycle resolution and severity drill-down contracts stay shared.
 */
export default function DashboardPage() {
  return <Suspense fallback={null}><DashboardContent /></Suspense>;
}

function DashboardContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { activeTenantId: tenantId } = useAuth();
  const scope = useMemo<DashboardFilterScope>(() => parseDashboardScope(searchParams), [searchParams]);
  const scopeKey = [tenantId, scope.projectId, scope.applicationId, scope.sbomId];
  const changeScope = useCallback((next: DashboardFilterScope) => {
    const params = new URLSearchParams();
    if (next.projectId) params.set('project', String(next.projectId));
    if (next.applicationId) params.set('application', String(next.applicationId));
    if (next.sbomId) params.set('sbom', String(next.sbomId));
    const query = params.toString();
    router.push(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }, [router, pathname]);

  const drilldownScope = useMemo(() => {
    const params = new URLSearchParams();
    if (scope.projectId) params.set('project', String(scope.projectId));
    if (scope.applicationId) params.set('product', String(scope.applicationId));
    if (scope.sbomId) params.set('sbom', String(scope.sbomId));
    return params.toString();
  }, [scope]);

  const summaryQuery = useQuery({
    queryKey: ['dashboard-summary', ...scopeKey],
    queryFn: ({ signal }) => getDashboardSummary(signal, scope),
    enabled: !!tenantId,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: 1,
  });

  // Same key + fetch as TopVulnerableSboms → shared cache, one network call.
  // Resolves which run a hero drill-down should land on.
  const topRunsQuery = useQuery({
    queryKey: ['top-vulnerable-runs', ...scopeKey],
    queryFn: ({ signal }) =>
      getDashboardRuns(scope, 'FINDINGS', 100, signal, true),
    enabled: !!tenantId,
  });

  const summary = summaryQuery.data;
  const posture = summary?.posture;
  const buckets = useMemo(
    () => aggregateRuns(topRunsQuery.data ?? []),
    [topRunsQuery.data],
  );

  // A severity is clickable whenever the portfolio has findings at that tier.
  //
  // The old gate also required `topRunForSeverity` to resolve, because the
  // click needed a run to open. The destination is now the portfolio-wide
  // Vulnerabilities tab, so no per-run target is needed and a tier with
  // findings is never a dead label.
  const interactiveSeverities = useMemo(() => {
    const set = new Set<SeverityKey>();
    for (const key of DRILLABLE_SEVERITIES) {
      if ((posture?.severity?.[key] ?? 0) > 0) set.add(key);
    }
    return set;
  }, [posture]);

  // A severity slice is portfolio-wide, so it opens the portfolio-wide list.
  //
  // This used to route to `topRunForSeverity(...)` — the single run with the
  // most findings of that severity — which showed a fraction of the number the
  // user had just clicked (77 of 289 High, in one real case). The
  // Vulnerabilities tab reads the same `findings.latest_per_sbom` scope as the
  // pie, so the count on the destination always matches the slice.
  const handleSegmentClick = useCallback(
    (key: SeverityKey) => {
      router.push(`/analysis?tab=vulnerabilities&severity=${key}${drilldownScope ? `&${drilldownScope}` : ''}`);
    },
    [router, drilldownScope],
  );

  // KEV / EPSS / Fix have no per-run column to rank by, so they land on the
  // most-vulnerable run (highest weighted severity) with the matching filter
  // pre-applied; the reconciliation banner frames portfolio-vs-run. Wired
  // whenever a target run exists — the tiles self-gate on count > 0.
  const topBucket = buckets[0];
  const handleKevClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?kev=1&globalCount=${posture?.kev_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleFixClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?fix=1&globalCount=${posture?.fix_available_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleEpssClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?epss=${HIGH_EPSS_PERCENTILE}&globalCount=${posture?.high_epss_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleReviewClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?review=1&globalCount=${posture?.needs_review_count ?? 0}`,
    );
  }, [topBucket, posture, router]);

  const needsReview = posture?.needs_review_count;

  return (
    <div className="dashboard-root flex flex-1 flex-col min-h-full">
      <TopBar
        title="Dashboard"
        subtitle="Security overview of your SBOM portfolio"
      />
      <div className="min-w-0 space-y-5 p-4 md:p-6">
        <DashboardFilters scope={scope} onChange={changeScope} isUpdating={summaryQuery.isFetching} />
        {summaryQuery.isError && <div role="alert" className="rounded-xl border border-border bg-surface p-4 text-sm text-hcl-muted">Unable to load this dashboard scope. <button className="rounded px-2 font-medium text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" onClick={() => void summaryQuery.refetch()} disabled={summaryQuery.isFetching}>Retry</button></div>}
        {summaryQuery.isSuccess && summary?.posture?.total_sboms === 0 && <DashboardEmptyState filtered={!!(scope.projectId || scope.applicationId || scope.sbomId)} onClear={() => changeScope({ projectId: null, applicationId: null, sbomId: null })} />}
        {!summaryQuery.isPending && scope.sbomId && summary?.posture?.total_sboms_analysed === 0 &&
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-hcl-muted">No successful analysis is available for this SBOM.</p>}
        {!summaryQuery.isPending && summary?.posture?.total_sboms_analysed > 0 && summary?.posture?.total_findings === 0 &&
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-hcl-muted">No findings match the selected dashboard scope.</p>}
        <AiConfigBanner />

        <section aria-label="Portfolio metrics" className="dashboard-kpis grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
          <CounterTiles posture={summary?.posture ?? null} isLoading={summaryQuery.isPending || (summaryQuery.isError && !summary)} scope={scope} />
          <LifetimeStats completedOnly data={summary?.lifetime} findingsTotal={summary?.posture?.total_findings} isLoading={summaryQuery.isPending || (summaryQuery.isError && !summary)} />
        </section>

        {summaryQuery.isSuccess && <>
          <section aria-label="Vulnerability intelligence" className="dashboard-primary-charts grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-[1.3fr_1.65fr_1fr]">
            <SeverityChart compact data={summary?.posture?.severity} isLoading={false} onSliceClick={handleSegmentClick} interactiveSeverities={interactiveSeverities} />
            <PortfolioTrend initial={summary?.trend} scope={scope} tenantId={tenantId} />
            <SeverityBars data={summary?.posture?.severity} loading={false} onSelect={handleSegmentClick} />
          </section>
          <PortfolioHealth health={summary?.health} lifecycle={summary?.lifecycle} vex={summary?.vex} loading={false} hasInventory={(summary?.posture?.total_sboms ?? 0) > 0} />
        </>}
        {summaryQuery.isPending && <div role="status" aria-label="Loading portfolio charts" className="h-64 animate-pulse rounded-xl border border-border bg-surface motion-reduce:animate-none" />}
        <DashboardOperations key={scopeKey.join(":")} scope={scope} tenantId={tenantId} />

        <details className="dashboard-advanced rounded-xl border border-border bg-surface p-4" open>
          <summary className="cursor-pointer rounded text-sm font-semibold text-hcl-navy focus-visible:ring-2 focus-visible:ring-hcl-blue">Advanced security intelligence <span className="ml-2 text-xs font-normal text-hcl-muted">Prioritization, investigation and portfolio analytics</span></summary>
          <div className="mt-5 space-y-5">
        {/* 1 — the decision */}
        <Motion preset="rise" delay={40}>
          <HeroPostureCard
            posture={summary?.posture}
            isLoading={summaryQuery.isLoading}
            onSegmentClick={handleSegmentClick}
            interactiveSeverities={interactiveSeverities}
            onKevClick={topBucket ? handleKevClick : undefined}
            onEpssClick={topBucket ? handleEpssClick : undefined}
            onCriticalClick={
              interactiveSeverities.has('critical')
                ? () => handleSegmentClick('critical')
                : undefined
            }
            onFixClick={topBucket ? handleFixClick : undefined}
          />
        </Motion>

        {/* 2 — what's changed (delta drives action more than totals) */}
        <Motion preset="rise" delay={60}>
          <WhatsNewStrip posture={summary?.posture} scope={scope} />
        </Motion>

        {/* 3 — the primary action */}
        <Motion preset="rise" delay={120}>
          <QuickActionsV2 primaryAction={summary?.posture?.primary_action} scope={scope} />
        </Motion>

        {!scope.projectId && <Motion preset="rise" delay={140}>
          <CopilotPanel />
        </Motion>}

        <VulnerabilityAgePie vulnerabilityAge={summary?.vulnerability_age ?? null} isLoading={summaryQuery.isLoading || summaryQuery.isError} scope={scope} />
        {/* Where to look first */}
        <Motion preset="rise" delay={260}>
          <TopVulnerableSboms scope={scope} tenantId={tenantId} />
        </Motion>

        {/* Needs-review — quiet, feature-gated until the Phase 2 aggregate. */}
        {needsReview != null && needsReview > 0 && (
          <Motion preset="rise" delay={210}>
            <button
              type="button"
              onClick={topBucket ? handleReviewClick : undefined}
              disabled={!topBucket}
              className="inline-flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-1.5 text-xs font-medium text-amber-800 transition-colors hover:bg-amber-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 disabled:cursor-default disabled:opacity-70 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200"
            >
              <ClipboardCheck className="h-3.5 w-3.5" aria-hidden />
              <strong className="font-metric tabular-nums">{needsReview.toLocaleString()}</strong>
              low-confidence findings need review
            </button>
          </Motion>
        )}

        {/* Trend explorer — granularity + application filter + fix/resolved */}
        <Motion preset="rise" delay={260}>
          <TrendExplorer scope={scope} tenantId={tenantId} />
        </Motion>

        {/* ── Dashboard v4 — Advanced Analytics ────────────────── */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={280}>
            <ForecastCard forecast={summary?.forecast ?? null} isLoading={summaryQuery.isLoading} />
          </Motion>
          <Motion preset="rise" delay={300}>
            <ExploitationOutlookCard exploitation={summary?.exploitation ?? null} isLoading={summaryQuery.isLoading} />
          </Motion>
        </div>

        <Motion preset="rise" delay={320}>
          <RemediationPanel
            remediation={summary?.remediation ?? null}
            remediationStats={summary?.remediation_stats ?? null}
            isLoading={summaryQuery.isLoading}
          />
        </Motion>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={340}>
            <PortfolioRiskMap riskMap={summary?.risk_map ?? null} isLoading={summaryQuery.isLoading} />
          </Motion>
          <Motion preset="rise" delay={360}>
            <RiskMatrixCard riskMatrix={summary?.risk_matrix ?? null} isLoading={summaryQuery.isLoading} />
          </Motion>
        </div>

        <details className="rounded-xl border border-border p-4">
          <summary className="cursor-pointer rounded text-sm font-semibold text-hcl-navy focus-visible:ring-2 focus-visible:ring-hcl-blue">Detailed lifecycle, completeness and VEX evidence</summary>
          <div className="mt-4"><LifecycleHealthTiles lifecycle={summary?.lifecycle ?? null} health={summary?.health ?? null} vex={summary?.vex ?? null} hasInventory={(summary?.posture?.total_sboms ?? 0) > 0} isLoading={summaryQuery.isLoading || summaryQuery.isError} /></div>
        </details>

        {/* Recent activity — supporting detail at the foot of the dashboard. */}
        <Motion preset="rise" delay={400}>
          <ActivityFeed scope={scope} tenantId={tenantId} />
        </Motion>
          </div>
        </details>
      </div>
    </div>
  );
}
