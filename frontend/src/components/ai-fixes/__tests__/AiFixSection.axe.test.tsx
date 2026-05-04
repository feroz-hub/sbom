// @vitest-environment jsdom
/**
 * Accessibility regression check for AiFixSection.
 *
 * Asserts axe-core reports zero violations on the cached-result render
 * — the most common state in production. Phase 4 §4.5 hard requirement.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { screen, waitFor } from '@testing-library/react';
import { AiFixSection } from '../AiFixSection';
import { renderWithProviders, SAMPLE_FIX_ENVELOPE_OK } from './test-utils';

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

describe('AiFixSection accessibility', () => {
  it('has zero axe violations on the cached-result render', async () => {
    getFindingAiFix.mockResolvedValue(SAMPLE_FIX_ENVELOPE_OK);
    const { container } = renderWithProviders(
      <AiFixSection findingId={1} providerLabel="anthropic" />,
    );
    await waitFor(() =>
      expect(
        screen.getByText(/actively-exploited remote code execution/i),
      ).toBeInTheDocument(),
    );

    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
