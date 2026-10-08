'use client';

import Link from 'next/link';
import { Sparkles } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getAnalysisConfig, type EffectiveAiStatus } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';

const providerNames: Record<string, string> = { gemini: 'Google Gemini', google_gemini: 'Google Gemini', openai: 'OpenAI', anthropic: 'Anthropic', ollama: 'Ollama', vllm: 'vLLM', custom_openai: 'Custom OpenAI-compatible', sarvam: 'Sarvam' };

export function aiStatusCopy(status: EffectiveAiStatus): [string, string] {
  switch (status.state) {
    case 'AVAILABLE': return ['AI Fix Generation available', status.source === 'TENANT' ? 'Using your tenant-managed AI provider.' : "Using HCLTech’s platform-managed AI configuration."];
    case 'DISABLED': return ['AI Fix Generation is disabled for this deployment.', 'Configuration may already exist, but this feature is currently unavailable.'];
    case 'CONFIGURATION_REQUIRED':
      if (!status.can_configure) return ['AI Fix Generation unavailable', status.source === 'TENANT'
        ? 'No AI provider is currently available for this tenant. A tenant AI override is active. Contact your Tenant Administrator to review it.'
        : 'No AI provider is currently available for this tenant. Contact your Tenant Administrator.'];
      if (status.source === 'TENANT') return ['AI configuration needs attention', 'A tenant AI override is active without an effective provider. Review the override or restore platform inheritance in AI Settings.'];
      return ['AI configuration required', 'An AI provider must be configured before AI Fix Generation can be used.'];
    case 'VERIFICATION_PENDING': return ['AI provider configured', 'Connection verification pending.'];
    case 'TEMPORARILY_UNAVAILABLE': return ['AI provider temporarily unavailable', 'The configured provider could not complete the latest connection check. Configuration remains saved.'];
    case 'CONFIGURATION_UNAVAILABLE': return ['AI configuration needs attention', status.can_configure ? 'The selected provider configuration cannot currently be used. Review its settings and verification results.' : 'The selected provider configuration cannot currently be used. Contact your Tenant Administrator.'];
    default: return ['AI status unavailable', 'Effective AI configuration could not be checked. Try again later.'];
  }
}

export function aiStatusRequestError(error: unknown): string {
  const status = typeof error === 'object' && error !== null && 'status' in error ? error.status : undefined;
  if (status === 401) return 'Authentication is required to check AI availability.';
  if (status === 403) return 'You are not authorized to view AI availability for this context.';
  if (status === 404) return 'AI status is not available from this deployment.';
  if (typeof status === 'number' && status >= 500) return 'Unable to determine AI status. Try again later.';
  return 'AI status is temporarily unavailable. Try again later.';
}

export function AiConfigBanner() {
  const { activeTenantId, isPlatformContext, user, isLoading: authLoading } = useAuth();
  const { data: config, isLoading, isError, error } = useQuery({
    queryKey: ['analysis-config', isPlatformContext ? 'platform' : activeTenantId, user?.userId ?? 'anonymous', [...(user?.permissions ?? [])].sort().join(',')],
    enabled: !authLoading,
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  if (authLoading || isLoading) return null;
  const status = config?.ai_status;
  if (isError || !status) return <div role="status" className="rounded-lg border border-border px-4 py-3 text-sm text-hcl-muted">{isError ? aiStatusRequestError(error) : 'AI availability could not be checked. Try again later.'}</div>;
  const [title, description] = aiStatusCopy(status);
  const configure = status.state === 'CONFIGURATION_REQUIRED' && status.source !== 'TENANT' && status.can_configure;
  const action = configure ? 'Configure AI' : status.can_view_settings ? 'View AI Settings' : null;
  return <section aria-label="AI availability" className="flex flex-col gap-3 rounded-lg border border-border bg-white px-4 py-3 text-sm dark:bg-background sm:flex-row sm:items-center sm:justify-between">
    <div className="flex min-w-0 items-start gap-2"><Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-hcl-blue" aria-hidden /><div><p className="font-semibold text-hcl-navy">{title}</p><p className="mt-1 text-hcl-muted">{description}</p>{status.configured && <p className="mt-1 text-xs text-hcl-muted">{status.source === 'TENANT' ? 'Tenant managed' : 'Platform managed'}{status.provider && ` · ${providerNames[status.provider] || status.provider}`}{status.available_for_tenant && ' · Available'}</p>}{status.available_for_tenant && status.can_invoke_ai === false && <p className="mt-1 text-xs text-hcl-muted">AI availability is shown for this tenant. Your current permissions do not allow AI Fix Generation.</p>}</div></div>
    {action && <Link className="shrink-0 rounded-md px-2 py-1 text-sm font-medium text-hcl-blue hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-hcl-blue" href={status.settings_scope === 'platform' ? '/platform/configuration/ai' : '/settings/ai'}>{action}</Link>}
  </section>;
}
