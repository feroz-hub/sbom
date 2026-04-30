// @vitest-environment jsdom
/**
 * Phase-3 dialog integration — covers the regression scenarios the prompt
 * called out as "tests that would have caught this":
 *
 *   * Modal renders the ``unrecognized`` banner for ``FOOBAR-123`` and
 *     fires NO network request.
 *   * Modal renders the ``ok`` body for the GHSA fixture.
 *   * Clicking an alias chip swaps the active id (via onSwitchCve).
 *   * Retry button is absent in ``unrecognized`` and ``not_found``;
 *     present in ``unreachable``.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { CveDetailDialog } from '../CveDetailDialog';
import type { CveRowSeed } from '../types';
import { FULL_DETAIL, NOT_FOUND_DETAIL, SEED, UNREACHABLE_DETAIL } from './fixtures';
import { renderWithProviders } from './test-utils';

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

function Harness({ initialId }: { initialId: string }) {
  const [active, setActive] = useState<{ id: string; seed: CveRowSeed } | null>({
    id: initialId,
    seed: { ...SEED, vuln_id: initialId },
  });
  return (
    <CveDetailDialog
      cveId={active?.id ?? null}
      seed={active?.seed ?? null}
      scanId={null}
      scanName={null}
      open={active !== null}
      onOpenChange={(open) => {
        if (!open) setActive(null);
      }}
      onSwitchCve={(newId) =>
        setActive((prev) => (prev ? { id: newId, seed: prev.seed } : prev))
      }
      reportIssueHref="https://example.com/report"
    />
  );
}

describe('CveDetailDialog — Phase 3 regressions', () => {
  it('unrecognized id: renders the banner with NO network request', async () => {
    renderWithProviders(<Harness initialId="FOOBAR-123" />);
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText("We don't recognize this advisory format")).toBeInTheDocument();
    // Critical: the API client was never called.
    expect(getCveDetail).not.toHaveBeenCalled();
    // No Retry button in the unrecognized state.
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
    // Report link is present.
    expect(screen.getByRole('link', { name: /report this issue/i })).toBeInTheDocument();
  });

  it('ok state: full data renders, no banner shown', async () => {
    getCveDetail.mockResolvedValue(FULL_DETAIL);
    renderWithProviders(<Harness initialId="GHSA-jfh8-c2jp-5v3q" />);
    await screen.findByRole('dialog');
    await waitFor(() => expect(screen.getByText(FULL_DETAIL.summary)).toBeInTheDocument());
    expect(getCveDetail).toHaveBeenCalledTimes(1);
    // No banner copy from any failure state.
    expect(screen.queryByText("We don't recognize this advisory format")).not.toBeInTheDocument();
    expect(screen.queryByText("Couldn't reach the CVE database")).not.toBeInTheDocument();
  });

  it('alias chip click swaps the active CVE; query re-fires under the new key', async () => {
    // GHSA-keyed payload whose aliases include a CVE — that CVE shows up
    // as a clickable chip in the header. Two calls expected: the GHSA
    // first, then the CVE after the click.
    const ghsaPayload = {
      ...FULL_DETAIL,
      cve_id: 'GHSA-jfh8-c2jp-5v3q',
      aliases: ['CVE-2021-44832', 'GHSA-jfh8-c2jp-5v3q'],
    };
    getCveDetail.mockResolvedValue(ghsaPayload);
    renderWithProviders(<Harness initialId="GHSA-jfh8-c2jp-5v3q" />);

    await waitFor(() => expect(getCveDetail).toHaveBeenCalledTimes(1));
    expect(getCveDetail).toHaveBeenCalledWith(
      expect.objectContaining({ cveId: 'GHSA-jfh8-c2jp-5v3q' }),
    );

    const aliasButton = await screen.findByRole('button', {
      name: /switch to alias cve-2021-44832/i,
    });
    await userEvent.click(aliasButton);

    await waitFor(() => expect(getCveDetail).toHaveBeenCalledTimes(2));
    expect(getCveDetail).toHaveBeenLastCalledWith(
      expect.objectContaining({ cveId: 'CVE-2021-44832' }),
    );
  });

  it('not_found: no Retry button in the banner', async () => {
    getCveDetail.mockResolvedValue(NOT_FOUND_DETAIL);
    renderWithProviders(<Harness initialId="CVE-2099-9001" />);
    await waitFor(() =>
      expect(screen.getByText('No advisory record found upstream')).toBeInTheDocument(),
    );
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('unreachable: Retry button is present and triggers a refetch', async () => {
    getCveDetail.mockResolvedValue(UNREACHABLE_DETAIL);
    renderWithProviders(<Harness initialId="CVE-2099-9001" />);
    await waitFor(() =>
      expect(screen.getByText("Couldn't reach the CVE database")).toBeInTheDocument(),
    );
    const before = getCveDetail.mock.calls.length;
    const retry = screen.getByRole('button', { name: /retry cve enrichment/i });
    await userEvent.click(retry);
    await waitFor(() => expect(getCveDetail.mock.calls.length).toBeGreaterThan(before));
  });
});
