/**
 * Shared providers + fixtures for the ai-fixes test suite.
 *
 * Mirrors the helper shape in ``components/vulnerabilities/CveDetailDialog/__tests__``
 * so existing patterns transfer cleanly.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import type {
  AiBatchProgress,
  AiFindingFixEnvelope,
  AiFixResult,
  AiUsageSummary,
} from '@/types/ai';

export function newQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface ProvidersProps {
  client?: QueryClient;
  children: ReactNode;
}

export function Providers({ client, children }: ProvidersProps) {
  const qc = client ?? newQueryClient();
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

export function renderWithProviders(
  ui: ReactElement,
  opts?: RenderOptions & { client?: QueryClient },
) {
  const { client, ...rest } = opts ?? {};
  return render(ui, {
    wrapper: ({ children }) => <Providers client={client}>{children}</Providers>,
    ...rest,
  });
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

export const SAMPLE_FIX_RESULT: AiFixResult = {
  finding_id: 1,
  vuln_id: 'CVE-2021-44832',
  component_name: 'log4j-core',
  component_version: '2.16.0',
  bundle: {
    remediation_prose: {
      summary_in_context:
        'This is an actively-exploited remote code execution vulnerability in log4j-core 2.16.0. ' +
        'Your direct dependency on org.apache.logging.log4j:log4j-core means any application code ' +
        'that processes attacker-controlled log messages is at risk.',
      exploitation_likelihood: 'actively_exploited',
      recommended_path:
        'Upgrade to 2.17.1 immediately. This is the minimum version that resolves CVE-2021-44832.',
      confidence: 'high',
    },
    upgrade_command: {
      ecosystem: 'Maven',
      command:
        '<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.17.1</version></dependency>',
      target_version: '2.17.1',
      rationale: 'Smallest semver-stable upgrade that includes the fix.',
      breaking_change_risk: 'minor',
      tested_against_data: true,
    },
    decision_recommendation: {
      priority: 'urgent',
      reasoning: [
        'Listed in CISA KEV as actively exploited',
        'CVSS 9.0 on a network-reachable attack vector',
        'EPSS percentile 100% — highest exploitation probability',
      ],
      citations: ['kev', 'nvd', 'epss', 'fix_version_data'],
      confidence: 'high',
      caveats: [],
    },
  },
  metadata: {
    cache_key: 'abc123',
    cache_hit: false,
    provider_used: 'anthropic',
    model_used: 'claude-sonnet-4-5',
    prompt_version: 'v1',
    schema_version: 1,
    total_cost_usd: 0.0042,
    generated_at: '2026-05-03T12:00:00+00:00',
    expires_at: '2026-05-10T12:00:00+00:00',
    age_seconds: 60,
  },
};

export const SAMPLE_FIX_ENVELOPE_OK: AiFindingFixEnvelope = {
  result: SAMPLE_FIX_RESULT,
  error: null,
};

export const SAMPLE_FIX_ENVELOPE_BUDGET_ERROR: AiFindingFixEnvelope = {
  result: null,
  error: {
    finding_id: 1,
    vuln_id: 'CVE-2021-44832',
    component_name: 'log4j-core',
    component_version: '2.16.0',
    error_code: 'budget_exceeded',
    message: 'AI budget exceeded at scope=per_day_org',
  },
};

export function makeBatchProgress(overrides: Partial<AiBatchProgress> = {}): AiBatchProgress {
  return {
    run_id: 42,
    status: 'in_progress',
    total: 1000,
    from_cache: 781,
    generated: 142,
    failed: 0,
    remaining: 77,
    cost_so_far_usd: 1.74,
    estimated_remaining_seconds: 38,
    estimated_remaining_cost_usd: 0.92,
    started_at: '2026-05-03T12:00:00+00:00',
    finished_at: null,
    last_error: null,
    cancel_requested: false,
    provider_used: 'anthropic',
    model_used: 'claude-sonnet-4-5',
    ...overrides,
  };
}

export const SAMPLE_USAGE_SUMMARY: AiUsageSummary = {
  today: {
    window_days: 1,
    total_calls: 12,
    total_cache_hits: 4,
    cache_hit_ratio: 0.333,
    total_cost_usd: 0.045,
    total_input_tokens: 12000,
    total_output_tokens: 6000,
  },
  last_30_days: {
    window_days: 30,
    total_calls: 240,
    total_cache_hits: 200,
    cache_hit_ratio: 0.833,
    total_cost_usd: 1.247,
    total_input_tokens: 240000,
    total_output_tokens: 120000,
  },
  by_purpose: [
    { label: 'fix_bundle', calls: 240, cost_usd: 1.247 },
  ],
  by_provider: [
    { label: 'anthropic', calls: 200, cost_usd: 1.0 },
    { label: 'openai', calls: 40, cost_usd: 0.247 },
  ],
  budget_caps_usd: {
    per_request_usd: 0.1,
    per_scan_usd: 5.0,
    per_day_org_usd: 50.0,
  },
  spent_today_usd: 0.045,
  daily_remaining_usd: 49.955,
};
