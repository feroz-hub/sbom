'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getSessionQuality, getSbomQuality } from '@/lib/api';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import type { QualityAssessment, QualityComparison } from '@/types/sbomQuality';

export function SbomQualityCard({ assessment, comparison, stale = false }: {
  assessment: QualityAssessment; comparison?: QualityComparison; stale?: boolean;
}) {
  const [findingsVisible, setFindingsVisible] = useState(false);
  if (!assessment.supported) return <section aria-label="SBOM Quality" className="shrink-0 rounded-lg border border-border p-4">
    <h2 className="font-semibold">SBOM Quality</h2><p className="text-sm">{assessment.reason}</p>
  </section>;
  const grade = assessment.grade.toLowerCase().replaceAll('_', ' ');
  return <section aria-label="SBOM Quality" className="min-w-0 shrink-0 rounded-lg border border-border bg-white p-4 dark:bg-slate-900">
    <h2 className="font-semibold">SBOM Quality</h2>
    <p className="text-2xl font-semibold">{Math.round(assessment.overall_score)} / 100 <span className="text-base capitalize">{grade}</span></p>
    <p className="text-sm">Validation: {assessment.validation_status} · Quality measures data completeness and integrity, separately from vulnerability severity.</p>
    {assessment.validation_report_truncated && <p className="text-sm">Displayed validation results are limited. Existing candidate approval completeness checks still apply.</p>}
    {stale && <Alert variant="warning">This quality comparison belongs to an earlier draft. Run repair again to assess the current candidate.</Alert>}
    {comparison && <div role="group" aria-label="Quality Improvement" className="mt-3 rounded border border-border p-3 text-sm">
      <h3 className="font-semibold">Quality Improvement</h3>
      <p>Before: {comparison.before.overall_score} · After: {comparison.after.overall_score}</p>
      {comparison.comparable && comparison.improvement !== null ? <p>Change: {comparison.improvement > 0 ? '+' : ''}{comparison.improvement} points</p> : <p>These assessments use different scoring policies or unsupported formats and cannot be compared.</p>}
      <p>Calculated from the actual source and retained repair candidate. Candidate validation: {comparison.after.validation_report_truncated ? 'Report limited — complete-validation approval policy applies' : comparison.after.validation_status}.</p>
      {comparison.dimensions.map(d => <p key={d.code}>{d.name}: {d.before} → {d.after}</p>)}
    </div>}
    <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
      {assessment.dimensions.map(d => <div key={d.code} className="flex min-w-0 justify-between gap-3">
        <dt>{d.name}</dt><dd className="shrink-0 font-medium">{d.metrics.eligible === 0 ? 'Not applicable' : d.score}</dd>
      </div>)}
    </dl>
    <Button size="sm" variant="secondary" className="mt-3" onClick={() => setFindingsVisible(!findingsVisible)}>{findingsVisible ? 'Hide Quality Findings' : 'View Quality Findings'}</Button>
    {findingsVisible && <div className="mt-3 max-h-80 space-y-2 overflow-auto" aria-label="Quality Findings">
      {assessment.findings.map((f, i) => <article key={`${f.code}-${i}`} className="min-w-0 rounded border border-border p-3 text-sm">
        <p><strong>{f.severity}</strong> · {f.message}</p><p className="break-all"><code>{f.path}</code></p>
        <p>Quality impact: {f.quality_impact} dimension points</p>
        <p>Auto-Repair: {!f.repairability_assessed ? 'Analysis required' : f.repairable ? 'Available for review' : 'Not available — manual review'}</p>
        {f.remediation && <p>{f.remediation}</p>}
      </article>)}
      {!assessment.findings.length && <p>No quality findings.</p>}
      {assessment.findings_truncated && <p>Displayed findings are limited. Scores include all assessed components.</p>}
    </div>}
    <p className="mt-2 break-all text-xs text-hcl-muted">Engine {assessment.engine_version} · SHA256 {assessment.artifact_hash}</p>
  </section>;
}

export function SbomQualityPanel({ sessionId, sbomId }: { sessionId?: string; sbomId?: number }) {
  const quality = useQuery({ queryKey: ['sbom-quality', sessionId ? 'session' : 'sbom', sessionId ?? sbomId],
    queryFn: ({ signal }) => sessionId ? getSessionQuality(sessionId, signal) : getSbomQuality(sbomId!, signal),
    enabled: Boolean(sessionId || sbomId), retry: false });
  if (quality.isPending) return <p role="status">Calculating SBOM quality…</p>;
  if (quality.error) return <Alert variant="warning">Quality assessment unavailable. Existing validation and repair remain available.</Alert>;
  if (!quality.data?.enabled || !quality.data.assessment) return null;
  return <SbomQualityCard assessment={quality.data.assessment} />;
}
