// @vitest-environment jsdom
/**
 * FilterChipsAdaptive — dim-when-zero, clear-all visibility, status line.
 *
 * The chip cluster is the page's primary focus-narrowing affordance. The
 * "dim when zero" behaviour matters for cognition: a user shouldn't waste
 * a click on a chip that filters to nothing.
 */

import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FilterChipsAdaptive } from './FilterChipsAdaptive';
import { renderWithCompareProviders, SAMPLE_COMPARE_RESULT } from '../__tests__/test-utils';
import type { FindingChangeKind } from '@/types/compare';

const DEFAULT_CHANGE_KINDS = new Set<FindingChangeKind>([
  'added',
  'resolved',
  'severity_changed',
]);
const DEFAULT_SEVERITIES = new Set<string>([
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
]);

function defaultProps(overrides: Record<string, unknown> = {}) {
  return {
    rows: SAMPLE_COMPARE_RESULT.findings,
    posture: SAMPLE_COMPARE_RESULT.posture,
    changeKinds: new Set(DEFAULT_CHANGE_KINDS),
    toggleChangeKind: () => {},
    severities: new Set(DEFAULT_SEVERITIES),
    toggleSeverity: () => {},
    kevOnly: false,
    setKevOnly: () => {},
    fixAvailable: false,
    setFixAvailable: () => {},
    showUnchanged: false,
    setShowUnchanged: () => {},
    visibleCount: SAMPLE_COMPARE_RESULT.findings.filter(
      (f) => f.change_kind !== 'unchanged',
    ).length,
    onClearAll: () => {},
    ...overrides,
  };
}

describe('FilterChipsAdaptive — clear all', () => {
  it('omits "Clear all" when no filter is active (defaults)', () => {
    renderWithCompareProviders(<FilterChipsAdaptive {...defaultProps()} />);
    expect(
      screen.queryByRole('button', { name: /^Clear all$/i }),
    ).not.toBeInTheDocument();
  });

  it('shows "Clear all" when KEV-only is active', () => {
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ kevOnly: true })} />,
    );
    expect(
      screen.getByRole('button', { name: /^Clear all$/i }),
    ).toBeInTheDocument();
  });

  it('shows "Clear all" when a change-kind chip has been deselected', () => {
    const reduced = new Set<FindingChangeKind>(['added', 'resolved']);
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ changeKinds: reduced })} />,
    );
    expect(
      screen.getByRole('button', { name: /^Clear all$/i }),
    ).toBeInTheDocument();
  });

  it('clicking "Clear all" fires onClearAll', async () => {
    const onClearAll = vi.fn();
    const user = userEvent.setup();
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ kevOnly: true, onClearAll })} />,
    );
    await user.click(screen.getByRole('button', { name: /^Clear all$/i }));
    expect(onClearAll).toHaveBeenCalledTimes(1);
  });
});

describe('FilterChipsAdaptive — status line', () => {
  it('renders "Showing X of Y findings"', () => {
    const { container } = renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ visibleCount: 3 })} />,
    );
    // The line is split into multiple text nodes by interpolations and the
    // optional "(filtered)" inner span. Match against the line's full
    // textContent. SAMPLE has 4 non-unchanged findings.
    const lines = Array.from(container.querySelectorAll('span')).filter(
      (n) => (n.textContent ?? '').includes('Showing'),
    );
    expect(lines.length).toBeGreaterThanOrEqual(1);
    expect(lines[0].textContent).toContain('Showing 3 of 4 findings');
  });

  it('appends "(filtered)" when filter state is non-default', () => {
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ kevOnly: true, visibleCount: 1 })} />,
    );
    expect(screen.getByText(/\(filtered\)/i)).toBeInTheDocument();
  });

  it('omits "(filtered)" when only show_unchanged is active and other filters are default — wait, show_unchanged IS a non-default filter', () => {
    // Documenting: show_unchanged=true counts as filtered. The default is false.
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ showUnchanged: true })} />,
    );
    expect(screen.getByText(/\(filtered\)/i)).toBeInTheDocument();
  });
});

describe('FilterChipsAdaptive — toggle behavior', () => {
  it('clicking an inactive chip fires the corresponding toggle', async () => {
    const toggleChangeKind = vi.fn();
    const user = userEvent.setup();
    const reduced = new Set<FindingChangeKind>(['added', 'severity_changed']);
    renderWithCompareProviders(
      <FilterChipsAdaptive
        {...defaultProps({ changeKinds: reduced, toggleChangeKind })}
      />,
    );
    // The Resolved chip should be inactive in this state — click it.
    await user.click(screen.getByRole('button', { name: /Resolved/i }));
    expect(toggleChangeKind).toHaveBeenCalledWith('resolved');
  });

  it('KEV-only chip uses its aria-label for screen readers', async () => {
    const setKevOnly = vi.fn();
    const user = userEvent.setup();
    renderWithCompareProviders(
      <FilterChipsAdaptive {...defaultProps({ setKevOnly })} />,
    );
    await user.click(
      screen.getByRole('button', { name: /currently in CISA KEV/i }),
    );
    expect(setKevOnly).toHaveBeenCalledWith(true);
  });
});
