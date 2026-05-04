'use client';

import Link from 'next/link';
import { ArrowRight, Sparkles, XOctagon } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useAiCredentialSettings, useAiCredentials } from '@/hooks/useAiCredentials';
import { getAnalysisConfig } from '@/lib/api';

/**
 * Drives the user toward configuring AI providers when the feature is
 * enabled but no credentials exist. Three states:
 *
 *   - kill switch active        → red banner, link to settings to re-enable
 *   - feature on, no providers  → primary CTA banner
 *   - configured                → renders nothing
 *
 * Hidden entirely when ``ai_fixes_enabled`` or ``ai_ui_config_enabled``
 * are off — non-admin deployments shouldn't see the prompt at all.
 */
export function AiConfigBanner() {
  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });

  const featureOn = Boolean(config?.ai_fixes_enabled && config?.ai_ui_config_enabled);

  const credentialsQuery = useAiCredentials({ enabled: featureOn });
  const settingsQuery = useAiCredentialSettings({ enabled: featureOn });

  if (configLoading || !featureOn) return null;

  // Silent fail for non-admin — credentials endpoint is protected; if it
  // 403s we don't render anything rather than show a half-loaded banner.
  if (credentialsQuery.isError || settingsQuery.isError) return null;
  if (credentialsQuery.isLoading || settingsQuery.isLoading) return null;

  const credentials = credentialsQuery.data ?? [];
  const killSwitch = settingsQuery.data?.kill_switch_active ?? false;

  if (killSwitch) {
    return (
      <div
        role="alert"
        className="flex items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm dark:border-red-900 dark:bg-red-950/40"
        data-testid="ai-config-banner-kill-switch"
      >
        <div className="flex items-center gap-2 text-red-800 dark:text-red-200">
          <XOctagon className="h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong className="font-semibold">AI features disabled by kill switch.</strong>{' '}
            Cached fixes remain readable; new generation is paused.
          </span>
        </div>
        <Link
          href="/settings/ai"
          className="inline-flex shrink-0 items-center gap-1 rounded-md border border-red-300 bg-white px-3 py-1.5 text-xs font-medium text-red-800 hover:bg-red-50 dark:border-red-800 dark:bg-red-950 dark:text-red-100 dark:hover:bg-red-900"
        >
          Re-enable <ArrowRight className="h-3 w-3" aria-hidden />
        </Link>
      </div>
    );
  }

  if (credentials.length === 0) {
    return (
      <div
        role="region"
        aria-label="AI configuration"
        className="flex items-center justify-between gap-3 rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-sm dark:border-primary/40 dark:bg-primary/10"
        data-testid="ai-config-banner-empty"
      >
        <div className="flex items-center gap-2 text-hcl-navy">
          <Sparkles className="h-4 w-4 shrink-0 text-primary" aria-hidden />
          <span>
            <strong className="font-semibold">AI fixes aren&rsquo;t configured yet.</strong>{' '}
            Add a provider — Gemini&rsquo;s free tier takes about a minute.
          </span>
        </div>
        <Link
          href="/settings/ai"
          className="inline-flex shrink-0 items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white shadow-elev-1 hover:bg-hcl-dark"
        >
          Set up a provider <ArrowRight className="h-3 w-3" aria-hidden />
        </Link>
      </div>
    );
  }

  return null;
}
