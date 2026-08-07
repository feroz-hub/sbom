// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HeroPostureCard } from './HeroPostureCard';
import type { DashboardPosture } from '@/types';

/**
 * The dashboard hero is the surface that read "All clear across 1 SBOM" while
 * OSV and NVD had assessed 0 of 69 components. Its headline comes from the
 * server's `headline_state` (finding counts only), so coverage has to gate it
 * explicitly — these tests are the lock.
 */
function posture(overrides: Partial<DashboardPosture>): DashboardPosture {
  return {
    severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: '2026-08-06T10:00:00Z',
    total_sboms: 1,
    total_active_projects: 1,
    total_findings: 0,
    headline_state: 'clean',
    ...overrides,
  };
}

const REPORTED_CASE = posture({
  coverage_status: 'incomplete',
  coverage_gap_sources: ['OSV', 'NVD'],
});

describe('HeroPostureCard — incomplete coverage', () => {
  it('does not claim All clear when sources could not assess the components', () => {
    render(<HeroPostureCard posture={REPORTED_CASE} isLoading={false} />);

    expect(screen.queryByText(/all clear/i)).not.toBeInTheDocument();
    expect(screen.getByText('Incomplete coverage across 1 SBOM.')).toBeInTheDocument();
  });

  it('explains the gap without implying the SBOM is vulnerability-free', () => {
    render(<HeroPostureCard posture={REPORTED_CASE} isLoading={false} />);

    expect(
      screen.getByText(/one or more configured sources could not assess all components/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Coverage gaps: OSV, NVD/)).toBeInTheDocument();
    expect(screen.queryByText(/no findings in scope/i)).not.toBeInTheDocument();
  });

  it('uses amber, not the green no-findings treatment', () => {
    render(<HeroPostureCard posture={REPORTED_CASE} isLoading={false} />);

    const bar = screen.getByText(/no findings reported · coverage incomplete/i);
    expect(bar.className).toMatch(/amber/);
    expect(bar.className).not.toMatch(/emerald/);

    const headline = screen.getByText('Incomplete coverage across 1 SBOM.');
    expect(headline.className).toMatch(/orange|amber/);
    expect(headline.className).not.toMatch(/emerald/);
  });

  it('says coverage is unassessed when the backend cannot tell', () => {
    render(
      <HeroPostureCard posture={posture({ coverage_status: 'unknown' })} isLoading={false} />,
    );

    expect(screen.queryByText(/all clear/i)).not.toBeInTheDocument();
    expect(screen.getByText('Coverage not fully assessed across 1 SBOM.')).toBeInTheDocument();
  });
});

describe('HeroPostureCard — complete coverage', () => {
  it('still shows All clear for a genuinely clean, fully covered scope', () => {
    render(
      <HeroPostureCard posture={posture({ coverage_status: 'complete' })} isLoading={false} />,
    );

    expect(screen.getByText('All clear across 1 SBOM.')).toBeInTheDocument();
    expect(screen.getByText(/no findings in scope/i)).toBeInTheDocument();
    expect(screen.queryByTestId('hero-coverage-warning')).not.toBeInTheDocument();
  });

  it('behaves exactly as before when the API omits the coverage field', () => {
    render(<HeroPostureCard posture={posture({})} isLoading={false} />);

    expect(screen.getByText('All clear across 1 SBOM.')).toBeInTheDocument();
  });
});

describe('HeroPostureCard — findings plus incomplete coverage', () => {
  it('keeps the vulnerability headline and adds the coverage warning', () => {
    render(
      <HeroPostureCard
        posture={posture({
          severity: { critical: 3, high: 1, medium: 0, low: 0, unknown: 0 },
          total_findings: 4,
          headline_state: 'criticals_no_kev',
          coverage_status: 'incomplete',
          coverage_gap_sources: ['OSV'],
        })}
        isLoading={false}
      />,
    );

    // Findings remain visible and lead the framing.
    expect(screen.getByText(/3 critical findings across 1 SBOM\./i)).toBeInTheDocument();
    // Coverage caveat is retained alongside.
    const warning = screen.getByTestId('hero-coverage-warning');
    expect(warning).toHaveTextContent(/could not assess all components/i);
    expect(warning).toHaveTextContent('Coverage gaps: OSV');
    expect(screen.queryByText(/all clear/i)).not.toBeInTheDocument();
  });
});
