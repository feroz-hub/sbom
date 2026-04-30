// @vitest-environment jsdom
/**
 * IdenticalRunsCard — three sub-states + CTA + isIdenticalRuns predicate.
 *
 * The card replaces the hero in the most-common production case (no diff,
 * just shared findings). Each sub-state must produce the right copy.
 */

import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  IdenticalRunsCard,
  isIdenticalRuns,
} from './IdenticalRunsCard';
import {
  renderWithCompareProviders,
  SAMPLE_COMPARE_RESULT,
} from '../__tests__/test-utils';
import type { CompareResult } from '@/types/compare';

function withZeroDiff(overrides: Partial<CompareResult['posture']> = {}): CompareResult {
  return {
    ...SAMPLE_COMPARE_RESULT,
    posture: {
      ...SAMPLE_COMPARE_RESULT.posture,
      findings_added_count: 0,
      findings_resolved_count: 0,
      findings_severity_changed_count: 0,
      findings_unchanged_count: 373,
      ...overrides,
    },
  };
}

describe('isIdenticalRuns', () => {
  it('returns true when every diff count is zero', () => {
    expect(isIdenticalRuns(withZeroDiff())).toBe(true);
  });

  it('returns false when any diff count is non-zero', () => {
    expect(isIdenticalRuns(SAMPLE_COMPARE_RESULT)).toBe(false);
  });
});

describe('IdenticalRunsCard — variants', () => {
  it('shared variant — both runs have findings, all matched', () => {
    renderWithCompareProviders(
      <IdenticalRunsCard
        result={withZeroDiff()}
        onViewSharedFindings={() => {}}
      />,
    );
    expect(screen.getByText('No changes detected.')).toBeInTheDocument();
    // Number of shared findings appears in body text + the CTA button.
    expect(screen.getAllByText(/373/).length).toBeGreaterThanOrEqual(1);
  });

  it('both-clean variant — both runs have zero findings', () => {
    const r = withZeroDiff({ findings_unchanged_count: 0 });
    r.run_a = { ...r.run_a, total_findings: 0 };
    r.run_b = { ...r.run_b, total_findings: 0 };

    renderWithCompareProviders(
      <IdenticalRunsCard result={r} onViewSharedFindings={() => {}} />,
    );
    expect(
      screen.getByText('No vulnerabilities in either run.'),
    ).toBeInTheDocument();
  });

  it('no-overlap variant — both runs non-empty but zero shared', () => {
    const r = withZeroDiff({ findings_unchanged_count: 0 });
    r.run_a = { ...r.run_a, total_findings: 5 };
    r.run_b = { ...r.run_b, total_findings: 8 };
    r.relationship = { ...r.relationship, same_sbom: false };

    renderWithCompareProviders(
      <IdenticalRunsCard result={r} onViewSharedFindings={() => {}} />,
    );
    expect(
      screen.getByText('No overlapping vulnerabilities.'),
    ).toBeInTheDocument();
  });
});

describe('IdenticalRunsCard — CTA', () => {
  it('shared variant renders a "View shared findings" CTA', () => {
    renderWithCompareProviders(
      <IdenticalRunsCard
        result={withZeroDiff()}
        onViewSharedFindings={() => {}}
      />,
    );
    expect(
      screen.getByRole('button', { name: /View shared findings/i }),
    ).toBeInTheDocument();
  });

  it('clicking CTA fires onViewSharedFindings', async () => {
    const user = userEvent.setup();
    const onView = vi.fn();
    renderWithCompareProviders(
      <IdenticalRunsCard
        result={withZeroDiff()}
        onViewSharedFindings={onView}
      />,
    );
    await user.click(screen.getByRole('button', { name: /View shared findings/i }));
    expect(onView).toHaveBeenCalledTimes(1);
  });

  it('both-clean variant does NOT render a CTA (nothing to view)', () => {
    const r = withZeroDiff({ findings_unchanged_count: 0 });
    r.run_a = { ...r.run_a, total_findings: 0 };
    r.run_b = { ...r.run_b, total_findings: 0 };

    renderWithCompareProviders(
      <IdenticalRunsCard result={r} onViewSharedFindings={() => {}} />,
    );
    expect(
      screen.queryByRole('button', { name: /View shared findings/i }),
    ).not.toBeInTheDocument();
  });
});

describe('IdenticalRunsCard — sub-line', () => {
  it('renders a re-scan time descriptor when same_sbom and days_between are present', () => {
    const r = withZeroDiff();
    r.relationship = {
      ...r.relationship,
      same_sbom: true,
      days_between: 0.46, // ~11 hours
    };
    renderWithCompareProviders(
      <IdenticalRunsCard result={r} onViewSharedFindings={() => {}} />,
    );
    // The sub-line phrasing for ~11 hours.
    expect(screen.getByText(/re-scanned 11h apart/i)).toBeInTheDocument();
  });
});
