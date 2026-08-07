import { describe, expect, it } from 'vitest';
import { runStatusDescription, runStatusShortLabel, sbomAnalysisShortLabel } from '@/lib/analysisRunStatusLabels';
import { sourceSummaryFromRun } from '@/lib/runSourceSummary';
import {
  coverageGapSources,
  runCoverageOutcome,
  sourceCoverageDetail,
  sourceCoverageReason,
  sourceCoverageState,
  sourceHasCoverageGap,
} from '@/lib/sourceCoverage';
import type { AnalysisRun, SourceQuerySummary } from '@/types';

const summary = (overrides: Partial<SourceQuerySummary>): SourceQuerySummary => ({
  source: 'OSV',
  queried: 69,
  matched: 0,
  no_match: 69,
  skipped: 0,
  errors: 0,
  status: 'complete',
  ...overrides,
});

const GITHUB_COMPLETE = summary({ source: 'GITHUB' });
const OSV_SKIPPED = summary({
  source: 'OSV',
  queried: 0,
  no_match: 0,
  skipped: 69,
  status: 'skipped',
  reason: 'missing_supported_package_identity',
});
const NVD_SKIPPED = summary({
  source: 'NVD',
  queried: 0,
  no_match: 0,
  skipped: 69,
  status: 'skipped',
  reason: 'missing_authoritative_cpe',
});

describe('sourceCoverageState', () => {
  it('is complete when the source queried everything', () => {
    expect(sourceCoverageState(GITHUB_COMPLETE)).toBe('complete');
    expect(sourceHasCoverageGap(GITHUB_COMPLETE)).toBe(false);
  });

  it('is skipped when the source assessed nothing', () => {
    expect(sourceCoverageState(OSV_SKIPPED)).toBe('skipped');
    expect(sourceHasCoverageGap(OSV_SKIPPED)).toBe(true);
  });

  it('is skipped for a disabled source', () => {
    expect(sourceCoverageState(summary({ status: 'disabled', queried: 0, skipped: 0 }))).toBe('skipped');
  });

  it('is skipped when zero were queried and some were withheld, whatever the status', () => {
    expect(sourceCoverageState(summary({ status: 'complete', queried: 0, skipped: 12 }))).toBe('skipped');
  });

  it('is partial when some components were assessed and some were not', () => {
    const partial = summary({ queried: 60, skipped: 9 });
    expect(sourceCoverageState(partial)).toBe('partial');
    // Partial coverage of a source that DID run is not a run-level gap —
    // matches source_has_coverage_gap() in app/sources/routing.py.
    expect(sourceHasCoverageGap(partial)).toBe(false);
  });

  it('is error when the source reported failures', () => {
    const errored = summary({ errors: 3 });
    expect(sourceCoverageState(errored)).toBe('error');
    expect(sourceHasCoverageGap(errored)).toBe(true);
  });

  it('does not treat an empty SBOM as a gap', () => {
    expect(sourceHasCoverageGap(summary({ queried: 0, skipped: 0, no_match: 0 }))).toBe(false);
  });
});

describe('coverageGapSources', () => {
  it('names the sources that assessed nothing, in order', () => {
    expect(coverageGapSources([GITHUB_COMPLETE, OSV_SKIPPED, NVD_SKIPPED])).toEqual(['OSV', 'NVD']);
  });

  it('returns nothing for full coverage or missing data', () => {
    expect(coverageGapSources([GITHUB_COMPLETE])).toEqual([]);
    expect(coverageGapSources(null)).toEqual([]);
    expect(coverageGapSources(undefined)).toEqual([]);
  });
});

describe('sourceCoverageReason', () => {
  it('renders known reason codes as readable copy', () => {
    expect(sourceCoverageReason(OSV_SKIPPED)).toBe('Missing supported package identity');
    expect(sourceCoverageReason(NVD_SKIPPED)).toBe('Missing authoritative CPE');
    expect(sourceCoverageReason(summary({ status: 'skipped', queried: 0, skipped: 1, reason: 'missing_credentials' }))).toBe(
      'Missing credentials',
    );
  });

  it('humanises unmapped codes instead of leaking snake_case', () => {
    expect(
      sourceCoverageReason(summary({ status: 'skipped', queried: 0, skipped: 1, reason: 'some_new_cpe_rule' })),
    ).toBe('Some new CPE rule');
  });

  it('falls back per source when the API recorded no reason', () => {
    expect(sourceCoverageReason(summary({ source: 'NVD', status: 'skipped', queried: 0, skipped: 5 }))).toBe(
      'Missing authoritative CPE',
    );
    expect(sourceCoverageReason(summary({ source: 'OSV', status: 'skipped', queried: 0, skipped: 5 }))).toBe(
      'Missing supported package identity',
    );
    expect(sourceCoverageReason(summary({ source: 'VULNDB', status: 'skipped', queried: 0, skipped: 5 }))).toBe(
      'Source assessed no components',
    );
  });

  it('gives no reason for a source that covered the SBOM', () => {
    expect(sourceCoverageReason(GITHUB_COMPLETE)).toBeUndefined();
  });
});

describe('sourceCoverageDetail', () => {
  it('reports the count that explains the state', () => {
    expect(sourceCoverageDetail(GITHUB_COMPLETE)).toBe('69 queried');
    expect(sourceCoverageDetail(OSV_SKIPPED)).toBe('69 skipped');
    expect(sourceCoverageDetail(summary({ queried: 60, skipped: 9 }))).toBe('60 queried · 9 skipped');
    expect(sourceCoverageDetail(summary({ queried: 69, errors: 1 }))).toBe('69 queried · 1 error');
  });
});

describe('runCoverageOutcome', () => {
  const fallback = runStatusDescription('PARTIAL');

  it('names the sources that could not assess the components', () => {
    const text = runCoverageOutcome('PARTIAL', [GITHUB_COMPLETE, OSV_SKIPPED, NVD_SKIPPED], fallback, 0);

    expect(text).toBe(
      'No vulnerabilities were reported by the sources that could run, but OSV and NVD could not assess these components. The result does not establish that the SBOM is vulnerability-free.',
    );
  });

  it('never asserts the SBOM is vulnerability-free', () => {
    const text = runCoverageOutcome('PARTIAL', [OSV_SKIPPED], fallback, 0);

    expect(text).toContain('does not establish that the SBOM is vulnerability-free');
    expect(text).not.toMatch(/reported no vulnerabilities\./i);
  });

  it('uses the generic PARTIAL copy when no summary explains the gap', () => {
    expect(runCoverageOutcome('PARTIAL', [], fallback, 0)).toBe(fallback);
    expect(runCoverageOutcome('PARTIAL', null, fallback, 0)).toBe(fallback);
  });

  it('leaves non-PARTIAL statuses to the per-status copy', () => {
    const okCopy = runStatusDescription('OK');
    expect(runCoverageOutcome('OK', [OSV_SKIPPED], okCopy, 0)).toBe(okCopy);
  });
});

describe('PARTIAL status copy', () => {
  it('says incomplete coverage, not source errors', () => {
    expect(runStatusShortLabel('PARTIAL')).toBe('Incomplete coverage');
    expect(sbomAnalysisShortLabel('PARTIAL')).toBe('Incomplete coverage');
  });

  it('describes unassessed components without claiming there are none', () => {
    const description = runStatusDescription('PARTIAL');

    expect(description).toBe(
      'The scan completed, but one or more vulnerability sources could not assess some or all components. Findings may be incomplete.',
    );
    expect(description).not.toMatch(/no vulnerabilities/i);
  });

  it('keeps OK copy clean and ERROR copy technical', () => {
    expect(runStatusShortLabel('OK')).toBe('No issues');
    expect(runStatusDescription('OK')).toContain('reported no vulnerabilities');
    expect(runStatusShortLabel('ERROR')).toBe('Run error');
    expect(runStatusDescription('ERROR')).toContain('failed with an error');
  });
});

describe('sourceSummaryFromRun', () => {
  const base = { source_summary: null, raw_report: null } as Pick<AnalysisRun, 'source_summary' | 'raw_report'>;

  it('prefers the top-level column', () => {
    expect(sourceSummaryFromRun({ ...base, source_summary: [OSV_SKIPPED] })).toEqual([OSV_SKIPPED]);
  });

  it('reads raw_report.source_summary', () => {
    expect(
      sourceSummaryFromRun({ ...base, raw_report: JSON.stringify({ source_summary: [OSV_SKIPPED] }) }),
    ).toEqual([OSV_SKIPPED]);
  });

  it('reads raw_report.analysis_metadata.source_summary', () => {
    expect(
      sourceSummaryFromRun({
        ...base,
        raw_report: JSON.stringify({ analysis_metadata: { source_summary: [NVD_SKIPPED] } }),
      }),
    ).toEqual([NVD_SKIPPED]);
  });

  it('degrades to an empty list on missing or unparseable payloads', () => {
    expect(sourceSummaryFromRun(null)).toEqual([]);
    expect(sourceSummaryFromRun(base)).toEqual([]);
    expect(sourceSummaryFromRun({ ...base, raw_report: '{not json' })).toEqual([]);
  });
});
