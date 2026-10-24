/**
 * Read the per-source summary off an analysis run.
 *
 * The API exposes it three ways depending on endpoint and payload age:
 * a top-level `source_summary` column, `raw_report.source_summary`, or
 * `raw_report.analysis_metadata.source_summary`. Every consumer needs the
 * same fallback chain, so it lives here once.
 */

import type { AnalysisRun, SourceQuerySummary } from '@/types';

interface RawReportShape {
  source_summary?: SourceQuerySummary[];
  analysis_metadata?: { source_summary?: SourceQuerySummary[] };
}

export function sourceSummaryFromRun(
  run: Pick<AnalysisRun, 'source_summary' | 'raw_report'> | null | undefined,
): SourceQuerySummary[] {
  if (!run) return [];
  if (Array.isArray(run.source_summary)) return run.source_summary;
  if (!run.raw_report) return [];
  try {
    const parsed = JSON.parse(run.raw_report) as RawReportShape;
    const summary = parsed.source_summary ?? parsed.analysis_metadata?.source_summary;
    return Array.isArray(summary) ? summary : [];
  } catch {
    return [];
  }
}
