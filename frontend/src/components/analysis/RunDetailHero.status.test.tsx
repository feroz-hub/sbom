// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RunDetailHero } from '@/components/analysis/RunDetailHero';
import type { AnalysisRun, SourceQuerySummary } from '@/types';

function run(overrides: Partial<AnalysisRun>): AnalysisRun {
  return {
    id: 5,
    sbom_id: 3,
    sbom_name: 'App',
    project_id: null,
    product_id: null,
    run_status: 'RUNNING',
    source: 'NVD,OSV,GITHUB',
    total_components: 0,
    components_with_cpe: 0,
    total_findings: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    unknown_count: 0,
    query_error_count: 0,
    duration_ms: 0,
    started_on: '2026-07-07T00:00:00Z',
    completed_on: '2026-07-07T00:00:00Z',
    error_message: null,
    ...overrides,
  };
}

/** The reported runtime case: GITHUB covered 69, OSV and NVD covered none. */
const INCOMPLETE_COVERAGE: SourceQuerySummary[] = [
  { source: 'GITHUB', queried: 69, matched: 0, no_match: 69, skipped: 0, errors: 0, status: 'complete' },
  {
    source: 'OSV',
    queried: 0,
    matched: 0,
    no_match: 0,
    skipped: 69,
    errors: 0,
    status: 'skipped',
    reason: 'missing_supported_package_identity',
  },
  {
    source: 'NVD',
    queried: 0,
    matched: 0,
    no_match: 0,
    skipped: 69,
    errors: 0,
    status: 'skipped',
    reason: 'missing_authoritative_cpe',
  },
];

const FULL_COVERAGE: SourceQuerySummary[] = [
  { source: 'GITHUB', queried: 69, matched: 0, no_match: 69, skipped: 0, errors: 0, status: 'complete' },
  { source: 'OSV', queried: 69, matched: 0, no_match: 69, skipped: 0, errors: 0, status: 'complete' },
  { source: 'NVD', queried: 69, matched: 0, no_match: 69, skipped: 0, errors: 0, status: 'success' },
];

describe('RunDetailHero lifecycle states', () => {
  it.each(['RUNNING', 'INTERRUPTED'] as const)('does not show All clear for %s runs', (runStatus) => {
    render(<RunDetailHero run={run({ run_status: runStatus })} findings={[]} />);

    expect(screen.getByText(runStatus === 'RUNNING' ? 'Running' : 'Interrupted')).toBeInTheDocument();
    expect(screen.queryByText('All clear')).not.toBeInTheDocument();
  });

  it('shows All clear only for completed clean runs', () => {
    render(<RunDetailHero run={run({ run_status: 'OK', total_components: 3 })} findings={[]} />);

    expect(screen.getByText('All clear')).toBeInTheDocument();
  });
});

describe('RunDetailHero incomplete coverage (PARTIAL)', () => {
  it('labels the run Incomplete coverage and never claims it is clean', () => {
    render(
      <RunDetailHero
        run={run({
          run_status: 'PARTIAL',
          total_components: 69,
          total_findings: 0,
          source_summary: INCOMPLETE_COVERAGE,
        })}
        findings={[]}
      />,
    );

    expect(screen.getByText('Incomplete coverage')).toBeInTheDocument();
    expect(screen.queryByText('All clear')).not.toBeInTheDocument();
    expect(screen.queryByText('Clean')).not.toBeInTheDocument();
    expect(screen.queryByText(/reported no vulnerabilities/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/CLEAR risk/i)).not.toBeInTheDocument();
  });

  it('still shows no clean copy when the run carries no source summary', () => {
    render(<RunDetailHero run={run({ run_status: 'PARTIAL', total_components: 69 })} findings={[]} />);

    expect(screen.getByText('Incomplete coverage')).toBeInTheDocument();
    expect(screen.queryByText('All clear')).not.toBeInTheDocument();
  });

  it('still shows real risk from the sources that did run', () => {
    render(
      <RunDetailHero
        run={run({ run_status: 'PARTIAL', total_findings: 1, source_summary: INCOMPLETE_COVERAGE })}
        findings={[
          {
            id: 1,
            vuln_id: 'CVE-2026-0001',
            severity: 'HIGH',
            risk_score: 61,
            in_kev: false,
          } as never,
        ]}
      />,
    );

    expect(screen.getByText('HIGH risk')).toBeInTheDocument();
    expect(screen.queryByText('All clear')).not.toBeInTheDocument();
  });

  it('flags the findings tile as coverage-incomplete instead of a pass', () => {
    render(
      <RunDetailHero
        run={run({ run_status: 'PARTIAL', total_findings: 0, source_summary: INCOMPLETE_COVERAGE })}
        findings={[]}
      />,
    );

    expect(screen.getByText('Coverage incomplete')).toBeInTheDocument();
  });
});

describe('RunDetailHero source coverage panel', () => {
  it('distinguishes complete from skipped sources and names the skip reason', () => {
    render(
      <RunDetailHero
        run={run({
          run_status: 'PARTIAL',
          total_components: 69,
          source_summary: INCOMPLETE_COVERAGE,
        })}
        findings={[]}
      />,
    );

    // Heading no longer claims every selected source was queried.
    expect(screen.getByText('Source coverage')).toBeInTheDocument();
    expect(screen.queryByText('Sources queried')).not.toBeInTheDocument();

    const panel = screen.getByTestId('source-coverage');
    expect(panel).toHaveTextContent('Complete');
    expect(panel).toHaveTextContent('69 queried');
    expect(panel).toHaveTextContent('Skipped');
    expect(panel).toHaveTextContent('69 skipped');
    // Skip reasons are surfaced, not hidden.
    expect(panel).toHaveTextContent('Missing supported package identity');
    expect(panel).toHaveTextContent('Missing authoritative CPE');
  });

  it('marks every source complete when coverage was full', () => {
    render(
      <RunDetailHero
        run={run({ run_status: 'OK', total_components: 69, source_summary: FULL_COVERAGE })}
        findings={[]}
      />,
    );

    const panel = screen.getByTestId('source-coverage');
    expect(panel).toHaveTextContent('GHSA');
    expect(panel).toHaveTextContent('OSV');
    expect(panel).toHaveTextContent('NVD');
    expect(panel).not.toHaveTextContent('Skipped');
    expect(panel).not.toHaveTextContent('Missing');
    expect(screen.getByText('All clear')).toBeInTheDocument();
  });

  it('falls back to plain source chips when the run has no summary', () => {
    render(<RunDetailHero run={run({ run_status: 'OK', total_components: 3 })} findings={[]} />);

    expect(screen.getByText('Source coverage')).toBeInTheDocument();
    expect(screen.queryByTestId('source-coverage')).not.toBeInTheDocument();
  });
});
