import { Suspense } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { CompareView } from '@/components/compare/CompareView';
import { CompareSkeleton } from '@/components/compare/states/CompareStates';
import CompareV1Page from './_v1/page';

/**
 * Compare runs route.
 *
 * Strangler pattern (ADR-0008 §1):
 *   - The v1 implementation is preserved at ``./_v1/page.tsx``. Next's App
 *     Router treats ``_*`` folders as PRIVATE — the v1 file does not
 *     produce a route. We import it as a regular component when the
 *     emergency kill-switch is enabled.
 *   - ``NEXT_PUBLIC_COMPARE_V1_FALLBACK=true`` flips the default export to
 *     the v1 component so users keep working with reduced fidelity if v2
 *     hits a critical bug. Backend Settings.compare_v1_fallback echoes the
 *     same value through ``GET /health`` so ops can verify deployment from
 *     a single curl. See ADR-0008 §1.1 for the verification protocol.
 *
 * `Suspense` boundary is required by Next 15 for ``useSearchParams`` use
 * inside child client components.
 */
export default function CompareRunsPage() {
  // ``process.env.NEXT_PUBLIC_*`` is statically inlined at build time, so
  // toggling the kill-switch always requires a redeploy. This is the
  // intended trade-off — emergency rollbacks are rare and we want the
  // bundle to fully shake out unused branch code in steady state.
  const fallbackEnabled =
    process.env.NEXT_PUBLIC_COMPARE_V1_FALLBACK === 'true';

  if (fallbackEnabled) {
    return (
      <>
        <V1FallbackBanner />
        <CompareV1Page />
      </>
    );
  }

  return (
    <Suspense
      fallback={
        <div className="flex flex-1 flex-col">
          <TopBar
            title="Compare runs"
            breadcrumbs={[
              { label: 'Analysis Runs', href: '/analysis' },
              { label: 'Compare' },
            ]}
          />
          <div className="p-6">
            <CompareSkeleton />
          </div>
        </div>
      }
    >
      <CompareView />
    </Suspense>
  );
}

function V1FallbackBanner() {
  return (
    <div
      role="status"
      className="flex items-center justify-center gap-2 border-b border-amber-300 bg-amber-50 px-4 py-2 text-xs font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200"
    >
      <span aria-hidden>⚠</span>
      Compare is temporarily running on v1 — full features will return shortly.
    </div>
  );
}
