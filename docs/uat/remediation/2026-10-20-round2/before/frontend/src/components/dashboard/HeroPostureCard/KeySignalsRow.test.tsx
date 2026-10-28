// @vitest-environment jsdom
/**
 * KeySignalsRow — the hero's decision tiles.
 *
 * Carries forward the KEV-count rendering lock (Bug 1) from the retired
 * HeroMetricRow, and locks the new behaviours: the likely-exploited (EPSS)
 * tile is feature-gated on `highEpssCount`, and a tile only becomes a button
 * when its count > 0 (no dead buttons).
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { KeySignalsRow } from './KeySignalsRow';

describe('KeySignalsRow — KEV count rendering (Bug 1 lock)', () => {
  it('renders kev_count verbatim', () => {
    render(<KeySignalsRow kevCount={10} criticalCount={0} fixCount={0} />);
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('Known Exploited Vulnerabilities')).toBeInTheDocument();
  });
});

describe('KeySignalsRow — EPSS tile feature gate', () => {
  it('omits the likely-exploited tile when highEpssCount is undefined', () => {
    render(<KeySignalsRow kevCount={1} criticalCount={1} fixCount={1} />);
    expect(screen.queryByText(/Likely exploited/i)).not.toBeInTheDocument();
  });

  it('shows the likely-exploited tile (with its count) when highEpssCount is provided', () => {
    render(
      <KeySignalsRow kevCount={1} highEpssCount={7} criticalCount={1} fixCount={1} />,
    );
    expect(screen.getByText(/Likely exploited/i)).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
  });
});

describe('KeySignalsRow — drill-down clickability (no dead buttons)', () => {
  it('makes a tile a button only when its count > 0 and a handler is wired', () => {
    const onKevClick = vi.fn();
    const onCriticalClick = vi.fn();
    render(
      <KeySignalsRow
        kevCount={4}
        criticalCount={0}
        fixCount={2}
        onKevClick={onKevClick}
        onCriticalClick={onCriticalClick}
        onFixClick={vi.fn()}
      />,
    );

    // KEV has a count → clickable.
    const kevBtn = screen.getByRole('button', { name: /Known Exploited Vulnerabilities/i });
    fireEvent.click(kevBtn);
    expect(onKevClick).toHaveBeenCalledTimes(1);

    // Critical is 0 → static, never a button (even though a handler was passed).
    expect(
      screen.queryByRole('button', { name: /Critical/i }),
    ).not.toBeInTheDocument();
    expect(onCriticalClick).not.toHaveBeenCalled();
  });
});
