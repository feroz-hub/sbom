/**
 * Shared providers + fixtures for the Phase 3 settings/ai test suite.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import type {
  AiConnectionTestResult,
  AiCredential,
  AiCredentialSettings,
  AiProviderCatalogEntry,
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

export const SAMPLE_GEMINI_FREE_CATALOG: AiProviderCatalogEntry = {
  name: 'gemini',
  display_name: 'Google Gemini',
  requires_api_key: true,
  requires_base_url: false,
  is_local: false,
  supports_free_tier: true,
  free_tier_rate_limit_rpm: 15,
  free_tier_daily_token_limit: 1_000_000,
  available_models: [
    {
      name: 'gemini-2.5-flash',
      display_name: 'Gemini 2.5 Flash',
      default_tier: 'free',
      notes: 'Free tier: 15 req/min',
    },
  ],
  docs_url: 'https://ai.google.dev/gemini-api/docs',
  api_key_url: 'https://aistudio.google.com/app/apikey',
  notes: 'Genuine free tier.',
};

export const SAMPLE_ANTHROPIC_PAID_CATALOG: AiProviderCatalogEntry = {
  name: 'anthropic',
  display_name: 'Anthropic Claude',
  requires_api_key: true,
  requires_base_url: false,
  is_local: false,
  supports_free_tier: false,
  free_tier_rate_limit_rpm: null,
  free_tier_daily_token_limit: null,
  available_models: [
    {
      name: 'claude-sonnet-4-5',
      display_name: 'Claude Sonnet 4.5',
      default_tier: 'paid',
      notes: '',
    },
  ],
  docs_url: 'https://docs.anthropic.com/en/api/messages',
  api_key_url: 'https://console.anthropic.com/settings/keys',
  notes: 'Production-grade reasoning.',
};

export const SAMPLE_CATALOG: AiProviderCatalogEntry[] = [
  SAMPLE_ANTHROPIC_PAID_CATALOG,
  SAMPLE_GEMINI_FREE_CATALOG,
];


export function makeCredential(overrides: Partial<AiCredential> = {}): AiCredential {
  return {
    id: 1,
    provider_name: 'anthropic',
    label: 'default',
    api_key_present: true,
    api_key_preview: 'sk-ant…AhB7',
    base_url: null,
    default_model: 'claude-sonnet-4-5',
    tier: 'paid',
    is_default: true,
    is_fallback: false,
    enabled: true,
    cost_per_1k_input_usd: 0.003,
    cost_per_1k_output_usd: 0.015,
    is_local: false,
    max_concurrent: 10,
    rate_per_minute: 50,
    created_at: '2026-05-04T12:00:00+00:00',
    updated_at: '2026-05-04T12:00:00+00:00',
    last_test_at: '2026-05-04T12:30:00+00:00',
    last_test_success: true,
    last_test_error: null,
    ...overrides,
  };
}


export const SAMPLE_SETTINGS: AiCredentialSettings = {
  feature_enabled: true,
  kill_switch_active: false,
  budget_per_request_usd: 0.10,
  budget_per_scan_usd: 5.00,
  budget_daily_usd: 5.00,
  updated_at: '2026-05-04T00:00:00+00:00',
  updated_by_user_id: null,
  source: 'db',
};


export function makeTestResult(
  overrides: Partial<AiConnectionTestResult> = {},
): AiConnectionTestResult {
  return {
    success: true,
    latency_ms: 412,
    detected_models: ['gemini-2.5-flash'],
    error_message: null,
    error_kind: null,
    provider: 'gemini',
    model_tested: 'gemini-2.5-flash',
    ...overrides,
  };
}
