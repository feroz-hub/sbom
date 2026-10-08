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
    case 'CONFIGURATION_REQUIRED': return ['AI configuration required', 'An AI provider must be configured before AI Fix Generation can be used.'];
    case 'VERIFICATION_PENDING': return ['AI provider configured', 'Connection verification pending.'];
    case 'TEMPORARILY_UNAVAILABLE': return ['AI provider temporarily unavailable', 'The configured provider could not complete the latest connection check. Configuration remains saved.'];
    case 'CONFIGURATION_UNAVAILABLE': return ['AI configuration needs attention', 'The selected provider configuration cannot currently be used. Review its settings and verification results.'];
    default: return ['AI status unavailable', 'Effective AI configuration could not be checked. Try again later.'];
  }
}

export function AiConfigBanner() {
  const { activeTenantId, isPlatformContext } = useAuth();
  const { data: config, isLoading, isError } = useQuery({
    queryKey: ['analysis-config', isPlatformContext ? 'platform' : activeTenantId],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  if (isLoading) return null;
  const status = config?.ai_status;
  if (isError || !status) return <div role="status" className="rounded-lg border border-border px-4 py-3 text-sm text-hcl-muted">AI availability could not be checked. Try again later.</div>;
  const [title, description] = aiStatusCopy(status);
  const configure = status.state === 'CONFIGURATION_REQUIRED' && status.can_configure;
  const action = configure ? 'Configure AI' : status.can_view_settings ? 'View AI Settings' : null;
  return <section aria-label="AI availability" className="flex flex-col gap-3 rounded-lg border border-border bg-white px-4 py-3 text-sm dark:bg-background sm:flex-row sm:items-center sm:justify-between">
    <div className="flex min-w-0 items-start gap-2"><Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-hcl-blue" aria-hidden /><div><p className="font-semibold text-hcl-navy">{title}</p><p className="mt-1 text-hcl-muted">{description}</p>{status.configured && <p className="mt-1 text-xs text-hcl-muted">{status.source === 'TENANT' ? 'Tenant managed' : 'Platform managed'}{status.provider && ` · ${providerNames[status.provider] || status.provider}`}{status.available_for_tenant && ' · Available'}</p>}</div></div>
    {action && <Link className="shrink-0 rounded-md px-2 py-1 text-sm font-medium text-hcl-blue hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-hcl-blue" href={status.settings_scope === 'platform' ? '/platform/configuration/ai' : '/settings/ai'}>{action}</Link>}
  </section>;
}
