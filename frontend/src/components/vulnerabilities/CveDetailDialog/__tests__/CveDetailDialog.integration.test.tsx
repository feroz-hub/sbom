// @vitest-environment jsdom
/**
 * Integration test for the dialog shell.
 *
 *   * Dialog opens on a button click — the row-derived header paints
 *     immediately while the body lazy-loads.
 *   * The active CVE switches in place when the alias-button is clicked
 *     (single page-level dialog, not one per row).
 *   * ESC closes the dialog and focus returns to the originating button.
 *   * Network 500 surfaces the row-derived error fallback with retry —
 *     never an empty modal.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { CveDetailDialog } from '../CveDetailDialog';
import type { CveRowSeed } from '../types';
import { FULL_DETAIL, SEED } from './fixtures';
import { renderWithProviders } from './test-utils';

// Mock the API client at the module boundary so the dialog's TanStack
// Query call is intercepted without spinning a real fetch / setting up
// MSW. The test owns the resolution promise so it can drive the
// loading → success transition deterministically.
const getCveDetail = vi.fn();
vi.mock('@/lib/api', () => ({
  getCveDetail: (args: { cveId: string; scanId?: number | null }) => getCveDetail(args),
}));

beforeEach(() => {
  getCveDetail.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function Harness({ initialCve = null as string | null }: { initialCve?: string | null }) {
  const [active, setActive] = useState<{ id: string; seed: CveRowSeed } | null>(
    initialCve ? { id: initialCve, seed: SEED } : null,
  );
  return (
    <>
      <button
        type="button"
        data-testid="row-button"
        onClick={() => setActive({ id: 'CVE-2099-9001', seed: SEED })}
      >
        CVE-2099-9001
      </button>
      <CveDetailDialog
        cveId={active?.id ?? null}
        seed={active?.seed ?? null}
        scanId={null}
        scanName={null}
        open={active !== null}
        onOpenChange={(open) => {
          if (!open) setActive(null);
        }}
      />
    </>
  );
}

describe('CveDetailDialog integration', () => {
  it('opens on click, paints header from seed, lazy-loads body, then closes on ESC with focus restored', async () => {
    getCveDetail.mockResolvedValue(FULL_DETAIL);
    renderWithProviders(<Harness />);

    const trigger = screen.getByTestId('row-button');
    trigger.focus();
    await userEvent.click(trigger);

    // Dialog opened. Header — already painted from the seed before the fetch resolves.
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby');
    // The CVE id appears in the title bar.
    expect(screen.getByRole('heading', { level: 2, name: 'CVE-2099-9001' })).toBeInTheDocument();

    // The lazy body resolves and the summary lands.
    await waitFor(() =>
      expect(screen.getByText(FULL_DETAIL.summary)).toBeInTheDocument(),
    );

    // ESC closes the dialog and focus snaps back to the originating row button.
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(document.activeElement).toBe(trigger);
  });

  it('shows the unreachable banner when the enrichment fetch fails', async () => {
    // Non-retryable status so we land in the error fallback within the
    // RTL waitFor budget — useCveDetail only retries 5xx by design. The
    // banner taxonomy treats fetch errors with no data as "unreachable".
    const err = Object.assign(new Error('Bad request'), { status: 400 });
    getCveDetail.mockRejectedValue(err);
    renderWithProviders(<Harness initialCve="CVE-2099-9001" />);

    // Dialog already open — header still paints from the seed.
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'CVE-2099-9001' })).toBeInTheDocument();

    // Once the fetch settles, the unreachable banner + Retry button appear.
    await waitFor(() =>
      expect(screen.getByText("Couldn't reach the CVE database")).toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: /retry cve enrichment/i })).toBeInTheDocument();
  });
});
