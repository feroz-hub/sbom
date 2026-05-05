// @vitest-environment jsdom
/**
 * Phase 4 row-selection tests for FindingsTable.
 *
 * Covers:
 *   - tri-state header checkbox semantics (none / some / all on the
 *     filtered view)
 *   - selection persistence across filter changes (selecting Critical
 *     rows then narrowing to a different filter does NOT deselect)
 *   - bulk toolbar surfaces count + severity summary + clear button
 *   - "Select all" only selects rows visible under the active filter
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { useState } from 'react';
import { FindingsTable } from './FindingsTable';
import { DEFAULT_FILTERS, type FindingsFilterState } from '@/lib/findingFilters';
import type { EnrichedFinding } from '@/types';

// The findings table imports useRunAiFixList — mock it so tests don't
// hit the network and the AI indicator column stays out of the way.
vi.mock('@/hooks/useAiFix', async () => ({
  useRunAiFixList: () => ({ data: undefined, isLoading: false, isError: false }),
}));

// Mock the CVE detail modal so jsdom doesn't have to render it.
vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: () => null,
  useCveHoverPrefetch: () => ({ onHoverStart: () => {}, onHoverEnd: () => {} }),
  findingToSeed: () => ({}),
}));

function makeFinding(
  id: number,
  overrides: Partial<EnrichedFinding> = {},
): EnrichedFinding {
  return {
    id,
    analysis_run_id: 1,
    vuln_id: `CVE-2099-${String(id).padStart(5, '0')}`,
    title: `finding ${id}`,
    description: null,
    severity: 'HIGH',
    score: 7.0,
    vector: null,
    published_on: null,
    reference_url: null,
    cwe: null,
    cpe: null,
    component_name: `pkg-${id}`,
    component_version: '1.0.0',
    fixed_versions: null,
    attack_vector: null,
    cvss_version: null,
    aliases: null,
    source: 'NVD',
    in_kev: false,
    epss: 0,
    epss_percentile: null,
    risk_score: 0,
    cve_aliases: [],
    ...overrides,
  } as EnrichedFinding;
}

function renderTable(args: {
  findings: EnrichedFinding[];
  initialFilter?: Partial<FindingsFilterState>;
  initialSelection?: Set<number>;
}) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  function Harness() {
    const [filter, setFilter] = useState<FindingsFilterState>({
      ...DEFAULT_FILTERS,
      ...(args.initialFilter ?? {}),
    });
    const [selection, setSelection] = useState<ReadonlySet<number>>(
      args.initialSelection ?? new Set(),
    );
    return (
      <div>
        <FindingsTable
          findings={args.findings}
          isLoading={false}
          error={null}
          filter={filter}
          onFilterChange={setFilter}
          selectedIds={selection}
          onSelectionChange={setSelection}
        />
      </div>
    );
  }

  const result = render(
    <QueryClientProvider client={qc}>
      <Harness />
    </QueryClientProvider>,
  );
  return result;
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('FindingsTable — selection column', () => {
  it('does not render the selection column when selectedIds is undefined', () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const findings = [makeFinding(1), makeFinding(2)];
    render(
      <QueryClientProvider client={qc}>
        <FindingsTable
          findings={findings}
          isLoading={false}
          error={null}
        />
      </QueryClientProvider>,
    );
    expect(screen.queryByTestId('findings-select-all')).toBeNull();
  });

  it('renders the header tri-state checkbox in "none" state when nothing is selected', () => {
    renderTable({ findings: [makeFinding(1), makeFinding(2)] });
    const header = screen.getByTestId('findings-select-all') as HTMLInputElement;
    expect(header.checked).toBe(false);
    expect(header.indeterminate).toBe(false);
  });

  it('selects every visible finding when the user clicks the header in "none" state', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderTable({
      findings: [
        makeFinding(1, { severity: 'CRITICAL' }),
        makeFinding(2, { severity: 'HIGH' }),
        makeFinding(3, { severity: 'MEDIUM' }),
      ],
    });
    await user.click(screen.getByTestId('findings-select-all'));
    await waitFor(() => {
      const summary = screen.getByTestId('selection-summary');
      // 3 selected, 3 distinct severities.
      expect(summary).toHaveTextContent('3 selected · across 3 severities');
    });
  });

  it('shows the indeterminate state when only some visible rows are selected', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderTable({ findings: [makeFinding(1), makeFinding(2), makeFinding(3)] });
    // Toggle only one row.
    const rowCheckbox = screen.getByTestId('finding-select-1') as HTMLInputElement;
    await user.click(rowCheckbox);
    await waitFor(() => {
      const header = screen.getByTestId('findings-select-all') as HTMLInputElement;
      expect(header.indeterminate).toBe(true);
    });
  });

  it('clearing via the bulk toolbar removes every selected id', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderTable({
      findings: [makeFinding(1), makeFinding(2)],
      initialSelection: new Set([1, 2]),
    });
    await user.click(screen.getByTestId('selection-clear'));
    await waitFor(() =>
      expect(screen.queryByTestId('selection-toolbar')).toBeNull(),
    );
  });
});

describe('FindingsTable — selection persists across filter changes', () => {
  it('keeps Critical rows selected when the filter narrows to High', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const findings = [
      makeFinding(1, { severity: 'CRITICAL' }),
      makeFinding(2, { severity: 'HIGH' }),
      makeFinding(3, { severity: 'CRITICAL' }),
    ];
    renderTable({
      findings,
      initialSelection: new Set([1, 3]),
    });
    // Both Criticals are pre-selected → toolbar shows 2 selected.
    expect(screen.getByTestId('selection-summary')).toHaveTextContent(
      '2 selected · across 1 severity',
    );

    // Apply a search filter that hides the Criticals (search by
    // component name "pkg-2"). The selection persists even though
    // the rows are no longer visible.
    const searchInput = screen.getByPlaceholderText(/search/i);
    await user.type(searchInput, 'pkg-2');
    await waitFor(() => {
      // Toolbar still says 2 selected — those rows are hidden but not
      // deselected.
      expect(screen.getByTestId('selection-summary')).toHaveTextContent(
        '2 selected',
      );
    });
  });

  it('"Select all" only adds findings visible under the active filter', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const findings = [
      makeFinding(1, { severity: 'CRITICAL', component_name: 'log4j-core' }),
      makeFinding(2, { severity: 'HIGH', component_name: 'requests' }),
      makeFinding(3, { severity: 'CRITICAL', component_name: 'log4j-api' }),
    ];
    renderTable({ findings });

    // Apply a search filter that hides finding 2.
    const searchInput = screen.getByPlaceholderText(/search/i);
    await user.type(searchInput, 'log4j');

    // Click "Select all" — only findings 1 and 3 should be selected.
    await user.click(screen.getByTestId('findings-select-all'));
    await waitFor(() => {
      // 2 selected, both CRITICAL → 1 severity.
      expect(screen.getByTestId('selection-summary')).toHaveTextContent(
        '2 selected · across 1 severity',
      );
    });
  });
});

describe('SelectionToolbar visibility', () => {
  it('does not render when nothing is selected', () => {
    renderTable({ findings: [makeFinding(1)] });
    expect(screen.queryByTestId('selection-toolbar')).toBeNull();
  });

  it('renders the count + severity summary when at least one row is selected', () => {
    renderTable({
      findings: [
        makeFinding(1, { severity: 'CRITICAL' }),
        makeFinding(2, { severity: 'HIGH' }),
      ],
      initialSelection: new Set([1, 2]),
    });
    const toolbar = screen.getByTestId('selection-toolbar');
    expect(within(toolbar).getByTestId('selection-summary')).toHaveTextContent(
      '2 selected · across 2 severities',
    );
  });

  it('singularises the severity copy for a single-severity selection', () => {
    renderTable({
      findings: [
        makeFinding(1, { severity: 'CRITICAL' }),
        makeFinding(2, { severity: 'CRITICAL' }),
      ],
      initialSelection: new Set([1, 2]),
    });
    expect(screen.getByTestId('selection-summary')).toHaveTextContent(
      '2 selected · across 1 severity',
    );
  });
});

describe('Selection-driven CTA precedence', () => {
  it('clicking the row checkbox triggers onSelectionChange with the new id set', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const onChange = vi.fn();
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <FindingsTable
          findings={[makeFinding(7, { severity: 'CRITICAL' })]}
          isLoading={false}
          error={null}
          filter={DEFAULT_FILTERS}
          onFilterChange={() => {}}
          selectedIds={new Set()}
          onSelectionChange={onChange}
        />
      </QueryClientProvider>,
    );

    // jsdom + uncontrolled-style click event bubble. Use fireEvent
    // directly rather than userEvent because the input is wrapped in
    // a Th cell with no label.
    const rowCheckbox = screen.getByTestId('finding-select-7');
    fireEvent.click(rowCheckbox);

    await waitFor(() => expect(onChange).toHaveBeenCalled());
    const lastCall = onChange.mock.calls.at(-1)![0] as Set<number>;
    expect(lastCall.has(7)).toBe(true);
  });
});
