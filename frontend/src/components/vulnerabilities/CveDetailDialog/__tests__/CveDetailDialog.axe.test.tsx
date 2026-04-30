// @vitest-environment jsdom
/**
 * Accessibility regression check via vitest-axe.
 *
 * Renders the dialog with full + KEV-listed data and asserts axe-core
 * reports zero violations. Specific rules to look out for:
 *   * dialog has aria-modal + aria-labelledby + aria-describedby
 *   * close button has accessible name
 *   * KEV / EPSS chips are not colour-only (text labels are present)
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { axe } from 'vitest-axe';
import { CveDetailDialog } from '../CveDetailDialog';
import { FULL_DETAIL, SEED } from './fixtures';
import { renderWithProviders } from './test-utils';
import { waitFor, screen } from '@testing-library/react';

const getCveDetail = vi.fn();
vi.mock('@/lib/api', () => ({
  getCveDetail: (args: { cveId: string; scanId?: number | null }) => getCveDetail(args),
}));

beforeEach(() => {
  getCveDetail.mockReset();
  getCveDetail.mockResolvedValue(FULL_DETAIL);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('CveDetailDialog accessibility', () => {
  it('has zero axe violations on the fully-populated, KEV-listed dialog', async () => {
    const { container } = renderWithProviders(
      <CveDetailDialog
        cveId="CVE-2099-9001"
        seed={SEED}
        scanId={null}
        scanName={null}
        open={true}
        onOpenChange={() => {}}
      />,
    );
    await waitFor(() =>
      expect(screen.getByText(FULL_DETAIL.summary)).toBeInTheDocument(),
    );

    const results = await axe(container);
    expect(results.violations).toEqual([]);
  }, 10_000);
});
