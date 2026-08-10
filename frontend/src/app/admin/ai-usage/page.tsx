'use client';

import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { CostDashboard } from '@/components/ai-fixes/Settings';
import { useAiSettings } from '@/hooks/useAiFix';
import { getAnalysisConfig } from '@/lib/api';

/**
 * Admin cost dashboard.
 *
 * Phase 5 §5.3 — operator-facing trend, breakdowns, top-N cache entries.
 * Distinct from the Settings page (which is read/write configuration);
 * this page is purely observability.
 */
export default function AiUsagePage() {
  const { data: config } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });

  const aiEnabled = Boolean(config?.ai_fixes_enabled);
  const { usage } = useAiSettings({ enabled: aiEnabled });

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="AI usage" />
      <main className="mx-auto w-full max-w-5xl space-y-8 px-6 py-6">
        {!aiEnabled ? (
          <p className="rounded-lg border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
            AI fix generation is not enabled for this deployment. Enable it in
            the deployment environment to populate the cost dashboard.
          </p>
        ) : (
          <CostDashboard usage={usage} />
        )}
      </main>
    </div>
  );
}
