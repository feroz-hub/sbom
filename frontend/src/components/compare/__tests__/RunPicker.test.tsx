// @vitest-environment jsdom
/**
 * RunPicker — keyboard navigation, search debounce, selection.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
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

    // Move to first option then second.
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}');
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

  it('renders "Same project as Run A" filter chip when paired project is given', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(
      <RunPicker
        label="Run B · candidate"
        selectedRunId={null}
        onSelect={() => {}}
        pairedRunProjectId={100}
      />,
    );
    await user.click(screen.getByRole('button', { name: /Choose a run/i }));
    // Wait for the recent runs to populate so the chip's neighbour list
    // is rendered.
    await screen.findByText('log4j-monorepo');
    expect(
      screen.getByLabelText(/Same project as Run A/i),
    ).toBeInTheDocument();
  });
});
