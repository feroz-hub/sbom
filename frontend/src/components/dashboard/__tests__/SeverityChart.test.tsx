// @vitest-environment jsdom
/**
 * "Vulnerability by Threat Level" pie (SeverityChart).
 *
 * Confirms the slice values + total reconcile with the same posture.severity
 * counts the hero bar consumes (incl. the unscored bucket), that drillable
 * slices use the shared drill handler, and that the unscored bucket is shown
 * but not clickable (no dead buttons).
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import type { ReactNode } from 'react';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { SeverityChart } from '@/components/dashboard/SeverityChart';

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }));

const wrap = (ui: ReactNode) => <ThemeProvider>{ui}</ThemeProvider>;

// Same shape getDashboardPosture returns (and the hero SeverityDistributionBar
// reads). 5 + 3 + 0 + 2 + 4 = 14 total, including the unscored bucket.
const DATA = { critical: 5, high: 3, medium: 0, low: 2, unknown: 4 };

describe('SeverityChart — reconciliation', () => {
  it('shows each non-zero slice count incl. unscored, and a total that sums to them', () => {
    render(wrap(<SeverityChart data={DATA} isLoading={false} title="Vulnerability by Threat Level" />));

    expect(screen.getByText('Vulnerability by Threat Level')).toBeInTheDocument();
    for (const [label, count] of [['Critical', '5'], ['High', '3'], ['Low', '2'], ['Unknown', '4']]) {
      expect(screen.getByText(label)).toBeInTheDocument();
      expect(screen.getByText(count)).toBeInTheDocument();
    }
    // Total (center + subtext) reflects the sum incl. the unscored bucket.
    expect(screen.getAllByText('14').length).toBeGreaterThan(0);
    // A zero slice is dropped (Medium = 0).
    expect(screen.queryByText('Medium')).toBeNull();
  });
});

describe('SeverityChart — drill-down', () => {
  it('drillable slice uses the shared handler; unscored is shown but not clickable', () => {
    const onSliceClick = vi.fn();
    render(
      wrap(
        <SeverityChart
          data={DATA}
          isLoading={false}
          onSliceClick={onSliceClick}
          interactiveSeverities={new Set(['critical', 'high', 'low'])}
        />,
      ),
    );

    fireEvent.click(screen.getByRole('button', { name: /View Critical findings/i }));
    expect(onSliceClick).toHaveBeenCalledWith('critical');

    // Unscored bucket is rendered (count visible) but NOT a button.
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Unknown/i })).toBeNull();
  });
});
