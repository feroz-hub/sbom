// @vitest-environment jsdom
/**
 * RunPicker — keyboard navigation, search debounce, selection, and the
 * "smart picker" grouping that surfaces other runs of the same logical
 * SBOM at the top of the dropdown.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunPicker } from '@/components/compare/SelectionBar/RunPicker';
import { renderWithCompareProviders } from './test-utils';
import type { RunSummary } from '@/types/compare';

const SAMPLE_RUNS: RunSummary[] = [
  {
    id: 10,
    sbom_id: 1,
    sbom_name: 'log4j-monorepo',
    project_id: 100,
    project_name: 'Backend',
    run_status: 'FINDINGS',
    completed_on: '2026-04-30T12:00:00Z',
    started_on: '2026-04-30T11:50:00Z',
    total_findings: 12,
    total_components: 50,
  },
  {
    id: 11,
    sbom_id: 2,
    sbom_name: 'web-frontend',
    project_id: 100,
    project_name: 'Backend',
    run_status: 'OK',
    completed_on: '2026-04-29T12:00:00Z',
    started_on: '2026-04-29T11:50:00Z',
    total_findings: 0,
    total_components: 30,
  },
  {
    id: 12,
    sbom_id: 3,
    sbom_name: 'mobile-android',
    project_id: 200,
    project_name: 'Mobile',
    run_status: 'PARTIAL',
    completed_on: '2026-04-28T12:00:00Z',
    started_on: '2026-04-28T11:50:00Z',
    total_findings: 5,
    total_components: 22,
  },
];

const recentRuns = vi.fn();
const searchRuns = vi.fn();
vi.mock('@/lib/api', () => ({
  recentRuns: (limit?: number, signal?: AbortSignal) => recentRuns(limit, signal),
  searchRuns: (q: string, limit?: number, signal?: AbortSignal) =>
    searchRuns(q, limit, signal),
}));

beforeEach(() => {
  recentRuns.mockReset();
  searchRuns.mockReset();
  recentRuns.mockResolvedValue(SAMPLE_RUNS);
  searchRuns.mockResolvedValue(SAMPLE_RUNS.slice(0, 1));
});

describe('RunPicker', () => {
  it('renders the placeholder when nothing is selected', () => {
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={() => {}}
      />,
    );
    expect(screen.getByRole('button', { expanded: false })).toHaveTextContent(
      /Choose a run/i,
    );
  });

  it('opens on click and lists recent runs', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={() => {}}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await waitFor(() => {
      expect(screen.getByRole('listbox')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText('log4j-monorepo')).toBeInTheDocument();
    });
    expect(recentRuns).toHaveBeenCalledTimes(1);
  });

  it('keyboard ArrowDown / Enter selects an option', async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={onSelect}
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await waitFor(() => screen.getByText('log4j-monorepo'));

    // After mount the active index defaults to the first option (id 10).
    // ArrowDown moves to the second (id 11), Enter fires onSelect.
    await user.keyboard('{ArrowDown}{Enter}');
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0].id).toBe(11);
  });

  it('Escape closes the listbox', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={() => {}}
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await waitFor(() => screen.getByText('log4j-monorepo'));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('typing fires the search query', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={() => {}}
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    const input = await screen.findByRole('combobox');
    await user.type(input, 'log4j');
    await waitFor(
      () => expect(searchRuns).toHaveBeenCalled(),
      { timeout: 1500 },
    );
    expect(searchRuns.mock.calls.at(-1)?.[0]).toBe('log4j');
  });

  it('uses the parent-supplied summary for the trigger label when the id is not in the recent list', async () => {
    // Repro for B-1: a shareable URL drops the user on a compare for a run
    // that isn't in the most-recent-20. Without the prop, the trigger reads
    // "Choose a run…" even though selectedRunId is set; with it, the trigger
    // reads the canonical name from the compare API response.
    recentRuns.mockResolvedValue([]); // simulate empty recent list
    const summary: RunSummary = {
      id: 999,
      sbom_id: 7,
      sbom_name: 'archived-service',
      project_id: 42,
      project_name: 'Legacy',
      run_status: 'FINDINGS',
      completed_on: '2026-01-15T08:00:00Z',
      started_on: '2026-01-15T07:50:00Z',
      total_findings: 3,
      total_components: 19,
    };
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={999}
        selectedRunSummary={summary}
        onSelect={() => {}}
      />,
    );
    expect(screen.getByRole('button')).toHaveTextContent(/archived-service/);
    expect(screen.getByRole('button')).toHaveTextContent(/#999/);
  });

  it('renders "Same project as Run A" filter chip when a paired run is given', async () => {
    const user = userEvent.setup();
    const paired: RunSummary = SAMPLE_RUNS[0];
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRun={paired}
        pairedRunLabel="Run A"
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    // Wait for the recent runs to populate so the chip's neighbour list
    // is rendered.
    await screen.findByText('web-frontend');
    expect(
      screen.getByLabelText(/Same project as Run A/i),
    ).toBeInTheDocument();
  });
});

// =============================================================================
// Smart-picker grouping (Phase 2 of "prioritize same-SBOM-different-date")
// =============================================================================

const PAIRED_LOG4J: RunSummary = SAMPLE_RUNS[0]; // sbom_name=log4j-monorepo, project_id=100

const MULTI_RUN_FIXTURE: RunSummary[] = [
  // Same SBOM as paired (log4j-monorepo @ project 100), older
  {
    ...SAMPLE_RUNS[0],
    id: 9,
    completed_on: '2026-04-25T12:00:00Z',
  },
  // Same SBOM as paired, even older
  {
    ...SAMPLE_RUNS[0],
    id: 8,
    completed_on: '2026-04-20T12:00:00Z',
  },
  // The paired run itself — should be excluded from the dropdown
  PAIRED_LOG4J,
  // Different SBOMs
  SAMPLE_RUNS[1],
  SAMPLE_RUNS[2],
];

describe('RunPicker — smart grouping', () => {
  it('renders an "Other runs of {sbom}" section when same-SBOM runs exist', async () => {
    recentRuns.mockResolvedValue(MULTI_RUN_FIXTURE);
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRun={PAIRED_LOG4J}
        pairedRunLabel="Run A"
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    // Primary section header is rendered with the paired SBOM name.
    expect(
      await screen.findByText(/Other runs of log4j-monorepo/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Other SBOMs/i)).toBeInTheDocument();
  });

  it('excludes the paired run from the dropdown (no degenerate self-compare)', async () => {
    recentRuns.mockResolvedValue(MULTI_RUN_FIXTURE);
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRun={PAIRED_LOG4J}
        pairedRunLabel="Run A"
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await screen.findByText(/Other runs of log4j-monorepo/i);

    // Only the OTHER log4j runs (#9, #8) should be visible — the paired
    // run #10 must not appear as a selectable option.
    const listbox = screen.getByRole('listbox');
    const optionIds = within(listbox)
      .getAllByRole('option')
      .map((el) => el.textContent ?? '');
    expect(optionIds.some((t) => t.includes('#10'))).toBe(false);
    expect(optionIds.some((t) => t.includes('#9'))).toBe(true);
    expect(optionIds.some((t) => t.includes('#8'))).toBe(true);
  });

  it('shows the single-run hint when the paired SBOM has no other runs', async () => {
    // Drop the same-SBOM siblings — only the paired run plus unrelated
    // SBOMs remain, mirroring the screenshot scenario where app-sbom #7
    // is the only run of its SBOM.
    recentRuns.mockResolvedValue([
      PAIRED_LOG4J,
      SAMPLE_RUNS[1],
      SAMPLE_RUNS[2],
    ]);
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRun={PAIRED_LOG4J}
        pairedRunLabel="Run A"
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await screen.findByText('web-frontend');

    expect(
      screen.getByText(/Only one run of/i),
    ).toBeInTheDocument();
    // The "Other runs of …" header must NOT appear when the primary
    // section is empty — that would look like a broken state.
    expect(
      screen.queryByText(/Other runs of log4j-monorepo/i),
    ).not.toBeInTheDocument();
  });

  it('falls back to a flat (legacy) list when no paired run is provided', async () => {
    recentRuns.mockResolvedValue(SAMPLE_RUNS);
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run A · baseline"
        selectedRunId={null}
        onSelect={() => {}}
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await screen.findByText('log4j-monorepo');

    expect(
      screen.queryByText(/Other runs of/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Other SBOMs/i)).not.toBeInTheDocument();
  });

  it('exposes role="group" with aria-labelledby for both sections', async () => {
    recentRuns.mockResolvedValue(MULTI_RUN_FIXTURE);
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRun={PAIRED_LOG4J}
        pairedRunLabel="Run A"
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    await screen.findByText(/Other runs of log4j-monorepo/i);

    const groups = screen.getAllByRole('group');
    expect(groups.length).toBeGreaterThanOrEqual(2);
    for (const group of groups) {
      expect(group).toHaveAttribute('aria-labelledby');
      const labelId = group.getAttribute('aria-labelledby');
      expect(labelId).toBeTruthy();
      // The label element must exist and have non-empty text content.
      const labelEl = labelId ? document.getElementById(labelId) : null;
      expect(labelEl).not.toBeNull();
      expect(labelEl?.textContent?.trim().length ?? 0).toBeGreaterThan(0);
    }
  });
});
