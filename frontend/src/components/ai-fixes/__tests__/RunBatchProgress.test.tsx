// @vitest-environment jsdom
/**
 * RunBatchProgress — banner shape across statuses.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunBatchProgress } from '../RunBatchProgress';
import { makeBatchProgress, renderWithProviders } from './test-utils';

const getRunAiFixProgress = vi.fn();
const triggerRunAiFixes = vi.fn();
const cancelRunAiFixes = vi.fn();
const getRunBatchEstimate = vi.fn();

vi.mock('@/lib/api', () => ({
  getRunAiFixProgress: (id: number, signal?: AbortSignal) => getRunAiFixProgress(id, signal),
  triggerRunAiFixes: (id: number, body: unknown, signal?: AbortSignal) =>
    triggerRunAiFixes(id, body, signal),
  cancelRunAiFixes: (id: number, signal?: AbortSignal) => cancelRunAiFixes(id, signal),
  aiFixStreamUrl: (id: number) => `http://test.local/api/v1/runs/${id}/ai-fixes/stream`,
  getRunBatchEstimate: (id: number, signal?: AbortSignal) => getRunBatchEstimate(id, signal),
}));

beforeEach(() => {
  getRunAiFixProgress.mockReset();
  triggerRunAiFixes.mockReset();
  cancelRunAiFixes.mockReset();
  getRunBatchEstimate.mockReset();
  // Default: low-cost estimate that does NOT trigger the warning. Tests
  // that need the warning override this in their own ``mockResolvedValue``.
  getRunBatchEstimate.mockResolvedValue({
    run_id: 42,
    findings_total: 0,
    findings_to_generate: 0,
    cached_count: 0,
    provider: 'anthropic',
    tier: 'paid',
    is_local: false,
    concurrency: 10,
    requests_per_minute: 50,
    estimated_seconds: 0,
    estimated_cost_usd: 0,
    bottleneck: 'cache',
    warning_recommended: false,
  });
  // EventSource isn't available in jsdom; the hook degrades to polling.
  Object.defineProperty(globalThis, 'EventSource', { value: undefined, configurable: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('RunBatchProgress', () => {
  it('shows the in-progress banner with cache + generated counts', async () => {
    getRunAiFixProgress.mockResolvedValue(makeBatchProgress());
    renderWithProviders(<RunBatchProgress runId={42} />);

    await waitFor(() => {
      expect(screen.getByText(/Generating AI remediation/i)).toBeInTheDocument();
    });
    expect(screen.getByText('Cached:')).toBeInTheDocument();
    expect(screen.getByText('Generated:')).toBeInTheDocument();
    // Cumulative cost.
    expect(screen.getByText(/\$1\.74/)).toBeInTheDocument();
  });

  it('renders the empty-state CTA when no batch has run yet', async () => {
    getRunAiFixProgress.mockResolvedValue(
      makeBatchProgress({
        status: 'pending',
        total: 0,
        from_cache: 0,
        generated: 0,
        failed: 0,
        remaining: 0,
        provider_used: null,
        model_used: null,
        cost_so_far_usd: 0,
        estimated_remaining_seconds: null,
      }),
    );
    renderWithProviders(<RunBatchProgress runId={1} />);
    await waitFor(() =>
      expect(screen.getByText(/Generate AI remediation for every finding/i)).toBeInTheDocument(),
    );
  });

  it('shows the budget-paused CTA pointing at Settings', async () => {
    getRunAiFixProgress.mockResolvedValue(
      makeBatchProgress({ status: 'paused_budget' }),
    );
    renderWithProviders(<RunBatchProgress runId={42} />);
    await waitFor(() =>
      expect(screen.getByText(/Daily AI budget reached/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole('link', { name: /Increase in Settings/i })).toHaveAttribute(
      'href',
      '/settings#ai',
    );
  });

  it('triggers a batch when the user clicks Generate', async () => {
    getRunAiFixProgress.mockResolvedValue(
      makeBatchProgress({
        status: 'pending',
        total: 0,
        from_cache: 0,
        generated: 0,
        failed: 0,
        remaining: 0,
      }),
    );
    triggerRunAiFixes.mockResolvedValue({
      progress: makeBatchProgress({ status: 'in_progress' }),
      enqueued: true,
    });
    renderWithProviders(<RunBatchProgress runId={5} />);
    await waitFor(() =>
      screen.getByRole('button', { name: /Generate AI fixes/i }),
    );
    await userEvent.click(screen.getByRole('button', { name: /Generate AI fixes/i }));
    await waitFor(() => expect(triggerRunAiFixes).toHaveBeenCalledTimes(1));
  });

  it('renders nothing when disabled', () => {
    const { container } = renderWithProviders(
      <RunBatchProgress runId={1} enabled={false} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('opens the free-tier warning dialog when the estimate flags it', async () => {
    getRunAiFixProgress.mockResolvedValue(
      makeBatchProgress({
        status: 'pending',
        total: 0,
        from_cache: 0,
        generated: 0,
        failed: 0,
        remaining: 0,
      }),
    );
    // Estimate flags ``warning_recommended=true`` (Gemini free tier on
    // a long batch). The trigger handler should open the dialog
    // instead of immediately firing the mutation.
    getRunBatchEstimate.mockResolvedValue({
      run_id: 42,
      findings_total: 1000,
      findings_to_generate: 800,
      cached_count: 200,
      provider: 'gemini',
      tier: 'free',
      is_local: false,
      concurrency: 4,
      requests_per_minute: 15,
      estimated_seconds: 12 * 60,
      estimated_cost_usd: 0,
      bottleneck: 'rate_limit',
      warning_recommended: true,
    });
    triggerRunAiFixes.mockResolvedValue({
      progress: makeBatchProgress({ status: 'in_progress' }),
      enqueued: true,
    });

    renderWithProviders(<RunBatchProgress runId={42} />);
    // Wait for the estimate to land so the trigger handler picks up
    // the warning flag.
    await waitFor(() => expect(getRunBatchEstimate).toHaveBeenCalled());
    await waitFor(() =>
      screen.getByRole('button', { name: /Generate AI fixes/i }),
    );

    // Click Generate — instead of triggering, the dialog appears.
    await userEvent.click(screen.getByRole('button', { name: /Generate AI fixes/i }));
    await waitFor(() => expect(screen.getByRole('alertdialog')).toBeInTheDocument());
    expect(screen.getByText(/Free tier rate limit detected/i)).toBeInTheDocument();
    // Trigger has NOT been called yet — the dialog gates it.
    expect(triggerRunAiFixes).not.toHaveBeenCalled();

    // Confirm — now trigger fires.
    await userEvent.click(
      screen.getByRole('button', { name: /Continue with gemini/i }),
    );
    await waitFor(() => expect(triggerRunAiFixes).toHaveBeenCalledTimes(1));
  });
});
