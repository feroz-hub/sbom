// @vitest-environment jsdom
/**
 * AiFixSection — empty / loading / cached / error / disabled states.
 *
 * Mocks ``@/lib/api`` so no real network calls fire. The hook layer
 * (useAiFix) is exercised end-to-end via TanStack Query against the
 * mocked client.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AiFixSection } from '../AiFixSection';
import {
  renderWithProviders,
  SAMPLE_FIX_ENVELOPE_BUDGET_ERROR,
  SAMPLE_FIX_ENVELOPE_OK,
} from './test-utils';

const getFindingAiFix = vi.fn();
const regenerateFindingAiFix = vi.fn();

vi.mock('@/lib/api', () => ({
  getFindingAiFix: (
    id: number,
    args: { providerName?: string | null },
    signal?: AbortSignal,
  ) => getFindingAiFix(id, args, signal),
  regenerateFindingAiFix: (
    id: number,
    args: { providerName?: string | null },
    signal?: AbortSignal,
  ) => regenerateFindingAiFix(id, args, signal),
}));

beforeEach(() => {
  getFindingAiFix.mockReset();
  regenerateFindingAiFix.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AiFixSection', () => {
  it('renders the disabled banner when the feature flag is off', () => {
    renderWithProviders(<AiFixSection findingId={1} enabled={false} />);
    expect(screen.getByText(/not enabled for this deployment/i)).toBeInTheDocument();
    expect(getFindingAiFix).not.toHaveBeenCalled();
  });

  it('shows the prose, command, decision, and metadata when the result lands', async () => {
    getFindingAiFix.mockResolvedValue(SAMPLE_FIX_ENVELOPE_OK);
    renderWithProviders(<AiFixSection findingId={1} providerLabel="anthropic" />);

    await waitFor(() => {
      expect(
        screen.getByText(/actively-exploited remote code execution/i),
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/Recommended fix · Maven/i)).toBeInTheDocument();
    expect(screen.getByText(/Decision recommendation/i)).toBeInTheDocument();
    expect(screen.getByText(/Priority: urgent/i)).toBeInTheDocument();
    expect(screen.getByText(/Generated/i)).toBeInTheDocument();
    expect(screen.getByText(/anthropic/)).toBeInTheDocument();
  });

  it('calls regenerate when the Regenerate button is clicked', async () => {
    getFindingAiFix.mockResolvedValue(SAMPLE_FIX_ENVELOPE_OK);
    regenerateFindingAiFix.mockResolvedValue(SAMPLE_FIX_ENVELOPE_OK);

    renderWithProviders(<AiFixSection findingId={1} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /regenerate/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /regenerate/i }));
    await waitFor(() => expect(regenerateFindingAiFix).toHaveBeenCalledTimes(1));
  });

  it('renders the budget-exceeded helper text when the API returns a structured error', async () => {
    getFindingAiFix.mockResolvedValue(SAMPLE_FIX_ENVELOPE_BUDGET_ERROR);
    renderWithProviders(<AiFixSection findingId={1} />);
    await waitFor(() =>
      expect(screen.getByText(/Daily AI budget reached/i)).toBeInTheDocument(),
    );
  });

  it('does NOT call the API when findingId is null', () => {
    renderWithProviders(<AiFixSection findingId={null} />);
    expect(getFindingAiFix).not.toHaveBeenCalled();
  });
});
