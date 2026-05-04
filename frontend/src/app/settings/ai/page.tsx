'use client';

import Link from 'next/link';
import { ChevronLeft } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { AiSettingsPage } from '@/components/settings/ai';
import { getAnalysisConfig } from '@/lib/api';

export default function AiSettingsRoute() {
  const { data: config } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });

  const aiEnabled = Boolean(config?.ai_fixes_enabled);
  const uiConfigEnabled = Boolean(config?.ai_ui_config_enabled);

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Settings — AI" />
      <main className="mx-auto w-full max-w-4xl space-y-4 px-6 py-6">
        <Link
          href="/settings"
          className="inline-flex items-center gap-1 text-xs text-hcl-muted hover:text-hcl-navy"
        >
          <ChevronLeft className="h-3.5 w-3.5" aria-hidden /> All settings
        </Link>

        {!aiEnabled ? (
          <p className="rounded-lg border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
            AI fix generation is not enabled for this deployment. Set
            <code className="mx-1">AI_FIXES_ENABLED=true</code> in the environment to make the
            surface available.
          </p>
        ) : !uiConfigEnabled ? (
          // Phase 4 §4.3 — rollout gate. The DB-backed UI surface is
          // available but operator hasn't flipped the flag yet. The
          // existing env-based AI fix generation continues to work; this
          // page just doesn't render the editable surface.
          <p className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
            UI configuration for AI providers is not yet enabled. The
            existing environment-based configuration continues to work
            unchanged. Set
            <code className="mx-1">AI_FIXES_UI_CONFIG_ENABLED=true</code>
            in the environment to flip this surface on. See the rollout
            playbook for details.
          </p>
        ) : (
          <AiSettingsPage />
        )}
      </main>
    </div>
  );
}
