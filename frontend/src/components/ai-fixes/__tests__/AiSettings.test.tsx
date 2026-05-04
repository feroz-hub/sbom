// @vitest-environment jsdom
/**
 * AiSettings — providers + caps + usage tiles.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { AiSettings } from '../Settings';
import { renderWithProviders, SAMPLE_USAGE_SUMMARY } from './test-utils';

const listAiProviders = vi.fn();
const listAiPricing = vi.fn();
const getAiUsageSummary = vi.fn();

vi.mock('@/lib/api', () => ({
  listAiProviders: (signal?: AbortSignal) => listAiProviders(signal),
  listAiPricing: (signal?: AbortSignal) => listAiPricing(signal),
  getAiUsageSummary: (signal?: AbortSignal) => getAiUsageSummary(signal),
}));

beforeEach(() => {
  listAiProviders.mockReset();
  listAiPricing.mockReset();
  getAiUsageSummary.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AiSettings', () => {
  it('renders providers and marks the configured default', async () => {
    listAiProviders.mockResolvedValue([
      {
        name: 'anthropic',
        available: true,
        default_model: 'claude-sonnet-4-5',
        supports_structured_output: true,
        is_local: false,
        notes: '',
      },
      {
        name: 'openai',
        available: false,
        default_model: 'gpt-4o-mini',
        supports_structured_output: true,
        is_local: false,
        notes: 'Disabled — no credentials configured.',
      },
    ]);
    listAiPricing.mockResolvedValue([]);
    getAiUsageSummary.mockResolvedValue(SAMPLE_USAGE_SUMMARY);

    renderWithProviders(<AiSettings defaultProvider="anthropic" />);

    // The providers section renders only after the listAiProviders query
    // resolves, so we anchor the wait on the section's heading.
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /^Providers$/i })).toBeInTheDocument(),
    );
    expect(screen.getAllByText(/anthropic/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/openai/i).length).toBeGreaterThan(0);
    expect(screen.getByText('default')).toBeInTheDocument();
    expect(screen.getByText(/no credentials configured/i)).toBeInTheDocument();
  });

  it('renders a disabled banner when feature flag is off', () => {
    renderWithProviders(<AiSettings enabled={false} />);
    expect(screen.getByText(/not enabled for this deployment/i)).toBeInTheDocument();
    expect(listAiProviders).not.toHaveBeenCalled();
  });

  it('shows usage totals once loaded', async () => {
    listAiProviders.mockResolvedValue([]);
    listAiPricing.mockResolvedValue([]);
    getAiUsageSummary.mockResolvedValue(SAMPLE_USAGE_SUMMARY);

    renderWithProviders(<AiSettings defaultProvider="anthropic" />);
    await waitFor(() =>
      expect(screen.getByText(/Usage this month/i)).toBeInTheDocument(),
    );
    // The dollar amount shows up in multiple places (total + per-purpose);
    // assert via the dt label so we anchor to the right tile.
    expect(screen.getByText(/Total cost/i).parentElement).toHaveTextContent('$1.25');
    expect(screen.getByText(/Cache hit rate/i).parentElement).toHaveTextContent('83.3%');
  });
});
