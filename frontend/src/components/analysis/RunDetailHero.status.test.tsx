// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RunDetailHero } from '@/components/analysis/RunDetailHero';
import type { AnalysisRun } from '@/types';

function run(overrides: Partial<AnalysisRun>): AnalysisRun {
  return {
    id: 5,
    sbom_id: 3,
    sbom_name: 'App',
    project_id: null,
    product_id: null,
    run_status: 'RUNNING',
    source: 'NVD,OSV,GITHUB,VULNDB',
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
