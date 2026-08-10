// @vitest-environment jsdom
/**
 * Axe sweep on the rendered AiSettingsPage with one credential present.
 * Phase 3 §3.11 hard rule.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { waitFor, screen } from '@testing-library/react';
import { AiSettingsPage } from '../AiSettingsPage';
import {
  SAMPLE_CATALOG,
  SAMPLE_SETTINGS,
  makeCredential,
  renderWithProviders,
} from './test-utils';


// Module-level mock fns so the vi.mock factory can reference them
// without hitting the "import hoisting" trap.
const listAiCredentials = vi.fn();
const listAiProviderCatalog = vi.fn();
const getAiCredentialSettings = vi.fn();
const listAiProviders = vi.fn();
const listAiPricing = vi.fn();
const getAiUsageSummary = vi.fn();


vi.mock('@/lib/api', () => ({
  listAiCredentials: () => listAiCredentials(),
  listAiProviderCatalog: () => listAiProviderCatalog(),
  getAiCredentialSettings: () => getAiCredentialSettings(),
  listAiProviders: () => listAiProviders(),
  listAiPricing: () => listAiPricing(),
  getAiUsageSummary: () => getAiUsageSummary(),
}));


beforeEach(() => {
  listAiCredentials.mockResolvedValue([makeCredential()]);
  listAiProviderCatalog.mockResolvedValue(SAMPLE_CATALOG);
  getAiCredentialSettings.mockResolvedValue(SAMPLE_SETTINGS);
  listAiProviders.mockResolvedValue([]);
  listAiPricing.mockResolvedValue([]);
  getAiUsageSummary.mockResolvedValue({
    today: { window_days: 1, total_calls: 0, total_cache_hits: 0, cache_hit_ratio: 0, total_cost_usd: 0, total_input_tokens: 0, total_output_tokens: 0 },
    last_30_days: { window_days: 30, total_calls: 0, total_cache_hits: 0, cache_hit_ratio: 0, total_cost_usd: 0, total_input_tokens: 0, total_output_tokens: 0 },
    by_purpose: [],
    by_provider: [],
    budget_caps_usd: { per_request_usd: 0.1, per_scan_usd: 5, per_day_org_usd: 5 },
    spent_today_usd: 0,
    daily_remaining_usd: 5,
  });
});
afterEach(() => vi.restoreAllMocks());


describe('AiSettingsPage accessibility', () => {
  it('has zero axe violations on the cached-render state', async () => {
    const { container } = renderWithProviders(<AiSettingsPage />);
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /AI Configuration/i })).toBeInTheDocument(),
    );
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
