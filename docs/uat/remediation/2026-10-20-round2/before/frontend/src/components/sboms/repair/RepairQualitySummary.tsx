'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getSessionQuality } from '@/lib/api';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';

export function RepairQualitySummary({ sessionId }: { sessionId: string }) {
  const [open, setOpen] = useState(false);
  const quality = useQuery({ queryKey: ['sbom-quality', 'session', sessionId], queryFn: ({ signal }) => getSessionQuality(sessionId, signal), retry: false });
  const assessment = quality.data?.assessment;
  if (quality.isPending) return <p className="text-xs text-hcl-muted" role="status">Loading SBOM quality…</p>;
  if (quality.isError) return <p className="text-xs text-hcl-muted">Quality assessment unavailable. Validation and repair remain available.</p>;
  if (!quality.data?.enabled || !assessment) return null;
  if (!assessment.supported) return <p className="text-xs text-hcl-muted">SBOM Quality: {assessment.reason}</p>;
  return <section aria-label="SBOM Quality" className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-border bg-surface px-3 py-2">
    <h2 className="text-xs font-semibold text-hcl-navy">SBOM Quality</h2>
    <div className="order-3 grid w-full min-w-0 grid-cols-3 sm:order-none sm:w-auto sm:flex-1 gap-x-4 gap-y-2 sm:grid-cols-6">
      {assessment.dimensions.map(dimension => <div key={dimension.code} className="min-w-0 text-[10px] text-hcl-muted"><div className="flex min-w-0 items-center justify-between gap-1"><span title={dimension.name} className="truncate">{dimension.name}</span><span className="shrink-0 font-semibold text-hcl-navy">{dimension.metrics.eligible === 0 ? 'N/A' : `${Math.round(dimension.score)}%`}</span></div>{dimension.metrics.eligible !== 0 && <div role="progressbar" aria-label={dimension.name} aria-valuemin={0} aria-valuemax={100} aria-valuenow={dimension.score} className="mt-1 h-1 overflow-hidden rounded bg-surface-muted"><div className="h-full rounded bg-hcl-blue/70" style={{ width: `${Math.max(0, Math.min(100, dimension.score))}%` }} /></div>}</div>)}
    </div>
    <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>View quality findings</Button>
    <Dialog open={open} onClose={() => setOpen(false)} title="SBOM Quality Findings" maxWidth="xl"><DialogBody><p className="mb-4 text-sm text-hcl-muted">Quality measures completeness and integrity. Validation determines whether this document can be imported.</p><div className="space-y-3">{assessment.findings.map((finding, index) => <article key={`${finding.code}-${index}`} className="min-w-0 rounded-lg border border-border p-3 text-sm"><p className="font-semibold">{finding.severity} · {finding.code}</p><p className="mt-1">{finding.message}</p>{finding.path && <p className="mt-1 break-all font-mono text-xs text-hcl-muted">{finding.path}</p>}{finding.remediation && <p className="mt-2 text-hcl-muted">{finding.remediation}</p>}<p className="mt-2 text-xs text-hcl-muted">Repairability: {!finding.repairability_assessed ? 'Not assessed' : finding.repairable ? 'Available for review' : 'Manual review'}</p></article>)}{!assessment.findings.length && <p>No quality findings.</p>}{assessment.findings_truncated && <p className="text-sm text-amber-800">Displayed findings are limited; scores include all assessed components.</p>}<details className="text-xs text-hcl-muted"><summary>Assessment details</summary><p>Overall score: {assessment.overall_score} / 100</p><p>Engine {assessment.engine_version}</p><p className="break-all">Artifact SHA-256: {assessment.artifact_hash}</p></details></div></DialogBody></Dialog>
  </section>;
}
