// @vitest-environment jsdom
/**
 * RunBatchProgress — banner shape across statuses + scope-aware modes.
 *
 * Tests cover:
 *   - the in-flight banner (counts, scope_label badge)
 *   - the idle CTA in three modes:
 *       all findings (no filter, no selection)
 *       filter-driven scope ("Critical findings", etc.)
 *       max-concurrent-reached (3 active batches)
 *   - the trigger flow with scope payload sent to the backend
 *   - the free-tier warning dialog gate
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunBatchProgress } from '../RunBatchProgress';
import { DEFAULT_FILTERS } from '@/lib/findingFilters';
import { makeBatchProgress, renderWithProviders } from './test-utils';

const getRunAiFixProgress = vi.fn();
const getRunAiBatch = vi.fn();
const triggerRunAiFixes = vi.fn();
const cancelRunAiFixes = vi.fn();
const cancelRunAiBatch = vi.fn();
const estimateRunAiFixesScoped = vi.fn();
const listRunAiBatches = vi.fn();

vi.mock('@/lib/api', () => ({
  getRunAiFixProgress: (id: number, signal?: AbortSignal) => getRunAiFixProgress(id, signal),
  getRunAiBatch: (runId: number, batchId: string, signal?: AbortSignal) =>
    getRunAiBatch(runId, batchId, signal),
  triggerRunAiFixes: (id: number, body: unknown, signal?: AbortSignal) =>
    triggerRunAiFixes(id, body, signal),
  cancelRunAiFixes: (id: number, signal?: AbortSignal) => cancelRunAiFixes(id, signal),
  cancelRunAiBatch: (runId: number, batchId: string, signal?: AbortSignal) =>
    cancelRunAiBatch(runId, batchId, signal),
  aiFixStreamUrl: (id: number) => `http://test.local/api/v1/runs/${id}/ai-fixes/stream`,
  aiFixBatchStreamUrl: (runId: number, batchId: string) =>
    `http://test.local/api/v1/runs/${runId}/ai-fixes/batches/${batchId}/stream`,
  estimateRunAiFixesScoped: (id: number, scope: unknown, signal?: AbortSignal) =>
    estimateRunAiFixesScoped(id, scope, signal),
  listRunAiBatches: (id: number, signal?: AbortSignal) => listRunAiBatches(id, signal),
}));

const DEFAULT_ESTIMATE = {
  run_id: 42,
  scope_label: null,
  total_findings_in_scope: 0,
  cached_count: 0,
  llm_call_count: 0,
  estimated_cost_usd: 0,
  estimated_seconds: 0,
  provider_name: 'anthropic',
  provider_tier: 'paid',
  is_local: false,
  rate_per_minute: 50,
  bottleneck: 'cache',
  warning_recommended: false,
  active_batches_using_provider: 0,
  blocked: false,
  blocked_reason: null,
};

const NO_ACTIVE_BATCHES = { run_id: 42, items: [], total: 0 };

beforeEach(() => {
  getRunAiFixProgress.mockReset();
  getRunAiBatch.mockReset();
  triggerRunAiFixes.mockReset();
  cancelRunAiFixes.mockReset();
  cancelRunAiBatch.mockReset();
  estimateRunAiFixesScoped.mockReset();
  listRunAiBatches.mockReset();
  // Defaults — paid tier, no contention, no warning. Tests override
  // when they need a different shape.
  estimateRunAiFixesScoped.mockResolvedValue(DEFAULT_ESTIMATE);
  listRunAiBatches.mockResolvedValue(NO_ACTIVE_BATCHES);
  // EventSource isn't available in jsdom; the hook degrades to polling.
  Object.defineProperty(globalThis, 'EventSource', { value: undefined, configurable: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('RunBatchProgress — in-flight banner', () => {
  it('shows the in-progress banner with cache + generated counts', async () => {
    getRunAiFixProgress.mockResolvedValue(makeBatchProgress());
    renderWithProviders(<RunBatchProgress runId={42} />);

    await waitFor(() => {
      expect(screen.getByText(/Generating AI remediation/i)).toBeInTheDocument();
    });
    expect(screen.getByText('Cached:')).toBeInTheDocument();
    expect(screen.getByText('Generated:')).toBeInTheDocument();
    expect(screen.getByText(/\$1\.74/)).toBeInTheDocument();
  });

  it('renders the scope_label badge on the in-flight banner', async () => {
    getRunAiFixProgress.mockResolvedValue(
      makeBatchProgress({
        // The progress envelope from the multi-batch backend carries
        // the human-readable scope label.
        scope_label: 'Critical findings',
      } as unknown as Record<string, unknown>),
    );
    renderWithProviders(<RunBatchProgress runId={42} />);
    await waitFor(() => {
      expect(screen.getByTestId('ai-batch-scope-label')).toHaveTextContent(
        'Critical findings',
      );
    });
  });
});

describe('RunBatchProgress — idle CTA (no scope)', () => {
  it('renders "Generate AI fixes for every finding" when no filter is supplied', async () => {
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
    // Run has 513 findings; estimate reports them as the in-scope total
    // since no filter is applied.
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 513,
      cached_count: 0,
      llm_call_count: 513,
    });
    renderWithProviders(<RunBatchProgress runId={1} />);
    await waitFor(() =>
      expect(
        screen.getByText(/Generate AI fixes for 513 findings in this run/i),
      ).toBeInTheDocument(),
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
  });

  it('renders nothing when disabled', () => {
    const { container } = renderWithProviders(
      <RunBatchProgress runId={1} enabled={false} />,
    );
    expect(container.firstChild).toBeNull();
  });
});

describe('RunBatchProgress — scope-aware CTA', () => {
  it('renders "Generate AI fixes for N critical findings" when filter is Critical', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      scope_label: 'Critical findings',
      total_findings_in_scope: 53,
      cached_count: 0,
      llm_call_count: 53,
      estimated_cost_usd: 0.32,
      estimated_seconds: 12,
    });
    renderWithProviders(
      <RunBatchProgress
        runId={4}
        filter={{ ...DEFAULT_FILTERS, severityFilter: 'CRITICAL' }}
      />,
    );
    await waitFor(() =>
      expect(screen.getByTestId('ai-batch-cta-label')).toHaveTextContent(
        /Generate AI fixes for 53 critical findings/i,
      ),
    );
  });

  it('renders the empty-scope copy when no findings match the filter', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 0,
      llm_call_count: 0,
    });
    renderWithProviders(
      <RunBatchProgress
        runId={4}
        filter={{ ...DEFAULT_FILTERS, search: 'definitely-no-match' }}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByText(/No findings match the current filters/i),
      ).toBeInTheDocument(),
    );
  });

  it('renders the all-cached copy when every scoped finding has a fix already', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      scope_label: 'Critical findings',
      total_findings_in_scope: 53,
      cached_count: 53,
      llm_call_count: 0,
    });
    renderWithProviders(
      <RunBatchProgress
        runId={4}
        filter={{ ...DEFAULT_FILTERS, severityFilter: 'CRITICAL' }}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByText(/All 53 findings already have cached AI fixes/i),
      ).toBeInTheDocument(),
    );
  });

  it('disables the trigger when 3 batches are already active on the run', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 50,
      cached_count: 0,
      llm_call_count: 50,
    });
    listRunAiBatches.mockResolvedValue({
      run_id: 4,
      total: 3,
      items: [
        {
          batch_id: 'b1',
          run_id: 4,
          status: 'in_progress',
          scope_label: 'Critical',
          provider_name: 'anthropic',
          total: 53,
          cached_count: 0,
          generated_count: 12,
          failed_count: 0,
          cost_usd: 0.05,
          started_at: '2026-05-04T00:00:00Z',
          completed_at: null,
          created_at: '2026-05-04T00:00:00Z',
          last_error: null,
        },
        {
          batch_id: 'b2',
          run_id: 4,
          status: 'in_progress',
          scope_label: 'KEV',
          provider_name: 'anthropic',
          total: 6,
          cached_count: 0,
          generated_count: 1,
          failed_count: 0,
          cost_usd: 0.01,
          started_at: '2026-05-04T00:00:00Z',
          completed_at: null,
          created_at: '2026-05-04T00:00:00Z',
          last_error: null,
        },
        {
          batch_id: 'b3',
          run_id: 4,
          status: 'queued',
          scope_label: 'High',
          provider_name: 'anthropic',
          total: 264,
          cached_count: 0,
          generated_count: 0,
          failed_count: 0,
          cost_usd: 0,
          started_at: null,
          completed_at: null,
          created_at: '2026-05-04T00:00:00Z',
          last_error: null,
        },
      ],
    });
    renderWithProviders(<RunBatchProgress runId={4} />);
    await waitFor(() =>
      expect(
        screen.getByText(/3 active batches on this run \(max concurrent reached\)/i),
      ).toBeInTheDocument(),
    );
    const button = screen.getByRole('button', { name: /Generate AI fixes/i });
    expect(button).toBeDisabled();
  });
});

describe('RunBatchProgress — selection precedence', () => {
  it('overrides filter scope when selectedIds is non-empty', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 12,
      cached_count: 4,
      llm_call_count: 8,
    });
    triggerRunAiFixes.mockResolvedValue({
      progress: makeBatchProgress({ status: 'in_progress' }),
      batch_id: 'sel-batch',
      enqueued: true,
      total: 12,
      cached_count: 4,
      scope_label: 'Selected (12)',
    });

    renderWithProviders(
      <RunBatchProgress
        runId={4}
        filter={{ ...DEFAULT_FILTERS, severityFilter: 'CRITICAL' }}
        selectedIds={[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]}
      />,
    );

    await waitFor(() =>
      expect(screen.getByTestId('ai-batch-cta-label')).toHaveTextContent(
        /Generate AI fixes for 12 selected findings/i,
      ),
    );

    await userEvent.click(screen.getByRole('button', { name: /Generate AI fixes/i }));
    await waitFor(() => expect(triggerRunAiFixes).toHaveBeenCalledTimes(1));
    const [, body] = triggerRunAiFixes.mock.calls[0]!;
    // Filter dimensions should NOT be in the payload — selection wins.
    expect(body).toMatchObject({
      scope: {
        finding_ids: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        label: 'Selected (12)',
      },
    });
    expect((body as Record<string, unknown>).scope).not.toHaveProperty('severities');
  });

  it('renders "Clear selection to use filters" affordance when onClearSelection is provided', async () => {
    const onClearSelection = vi.fn();
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 3,
      llm_call_count: 3,
    });
    renderWithProviders(
      <RunBatchProgress
        runId={4}
        selectedIds={[1, 2, 3]}
        onClearSelection={onClearSelection}
      />,
    );
    await waitFor(() =>
      screen.getByTestId('ai-batch-clear-selection'),
    );
    await userEvent.click(screen.getByTestId('ai-batch-clear-selection'));
    expect(onClearSelection).toHaveBeenCalledTimes(1);
  });
});


describe('RunBatchProgress — trigger payload', () => {
  it('sends the resolved scope to the backend trigger endpoint', async () => {
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 53,
      cached_count: 0,
      llm_call_count: 53,
    });
    triggerRunAiFixes.mockResolvedValue({
      progress: makeBatchProgress({ status: 'in_progress' }),
      batch_id: 'new-batch-id',
      enqueued: true,
      total: 53,
      cached_count: 0,
      scope_label: 'Critical findings',
    });
    renderWithProviders(
      <RunBatchProgress
        runId={5}
        filter={{ ...DEFAULT_FILTERS, severityFilter: 'CRITICAL' }}
      />,
    );
    await waitFor(() =>
      screen.getByRole('button', { name: /Generate AI fixes/i }),
    );
    await userEvent.click(
      screen.getByRole('button', { name: /Generate AI fixes/i }),
    );
    await waitFor(() => expect(triggerRunAiFixes).toHaveBeenCalledTimes(1));
    const [, body] = triggerRunAiFixes.mock.calls[0]!;
    expect(body).toMatchObject({
      scope: expect.objectContaining({
        severities: ['CRITICAL'],
        label: 'Critical findings',
      }),
    });
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
    estimateRunAiFixesScoped.mockResolvedValue({
      ...DEFAULT_ESTIMATE,
      total_findings_in_scope: 1000,
      cached_count: 200,
      llm_call_count: 800,
      provider_name: 'gemini',
      provider_tier: 'free',
      rate_per_minute: 15,
      estimated_seconds: 12 * 60,
      bottleneck: 'rate_limit',
      warning_recommended: true,
    });
    triggerRunAiFixes.mockResolvedValue({
      progress: makeBatchProgress({ status: 'in_progress' }),
      batch_id: 'b',
      enqueued: true,
      total: 1000,
      cached_count: 200,
    });

    renderWithProviders(<RunBatchProgress runId={42} />);
    await waitFor(() => expect(estimateRunAiFixesScoped).toHaveBeenCalled());
    await waitFor(() =>
      screen.getByRole('button', { name: /Generate AI fixes/i }),
    );

    await userEvent.click(screen.getByRole('button', { name: /Generate AI fixes/i }));
    await waitFor(() => expect(screen.getByRole('alertdialog')).toBeInTheDocument());
    expect(screen.getByText(/Free tier rate limit detected/i)).toBeInTheDocument();
    expect(triggerRunAiFixes).not.toHaveBeenCalled();

    await userEvent.click(
      screen.getByRole('button', { name: /Continue with gemini/i }),
    );
    await waitFor(() => expect(triggerRunAiFixes).toHaveBeenCalledTimes(1));
  });
});
