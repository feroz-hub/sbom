// @vitest-environment jsdom
/**
 * WhatsNewStrip — the delta-since-last-week signal.
 *
 * Carries forward the net-7day locks from the retired HeroMetricRow:
 *   * is_first_period === true → "first scan this week" copy, never "+N / −0"
 *     (Bug 5 lock).
 *   * the net_7day envelope is preferred over the flat aliases when both ship;
 *     the flat aliases are the fallback when the envelope is absent.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { WhatsNewStrip } from './WhatsNewStrip';
import type { DashboardPosture } from '@/types';

function makePosture(overrides: Partial<DashboardPosture> = {}): DashboardPosture {
  return {
    severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: null,
    total_sboms: 1,
    total_active_projects: 1,
    ...overrides,
  };
}

describe('WhatsNewStrip — first period (Bug 5 lock)', () => {
  it('renders the first-scan copy and never the misleading +N / −0', () => {
    render(
      <WhatsNewStrip
        posture={makePosture({
          net_7day: { added: 513, resolved: 0, is_first_period: true, window_days: 7 },
        })}
      />,
    );
    expect(screen.getByText(/first scan this week/i)).toBeInTheDocument();
    expect(screen.queryByText(/513/)).not.toBeInTheDocument();
  });
});

describe('WhatsNewStrip — delta rendering', () => {
  it('renders +added / −resolved when not first period', () => {
    render(
      <WhatsNewStrip
        posture={makePosture({
          net_7day: { added: 12, resolved: 5, is_first_period: false, window_days: 7 },
        })}
      />,
    );
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText(/new/i)).toBeInTheDocument();
    expect(screen.getByText(/resolved/i)).toBeInTheDocument();
  });

  it('prefers the net_7day envelope over the flat aliases', () => {
    render(
      <WhatsNewStrip
        posture={makePosture({
          net_7day: { added: 100, resolved: 40, is_first_period: false, window_days: 7 },
          net_7day_added: 999,
          net_7day_resolved: 999,
        })}
      />,
    );
    expect(screen.getByText('100')).toBeInTheDocument();
    expect(screen.getByText('40')).toBeInTheDocument();
    expect(screen.queryByText(/999/)).not.toBeInTheDocument();
  });

  it('falls back to the flat aliases when the envelope is absent', () => {
    render(
      <WhatsNewStrip
        posture={makePosture({ net_7day_added: 4, net_7day_resolved: 1 })}
      />,
    );
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
  });
});

describe('WhatsNewStrip — loading', () => {
  it('renders nothing until posture is available', () => {
    const { container } = render(<WhatsNewStrip posture={undefined} />);
    expect(container.firstChild).toBeNull();
  });
});
