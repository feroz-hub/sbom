'use client';

/**
 * Secure Component Advisor — recommendation review (spec Step 9;
 * FR-SCA-011..021, US-SCA-09..14).
 *
 * Source component, then candidates in review order (same-family versions
 * first) with type, rank, confidence, adoption, vulnerability history,
 * lifecycle, license, compatibility, freshness, reasons and limitations.
 * Actions — View evidence, Recommend, Accept, Reject, Defer, Request more
 * evidence, Close — appear only where the backend's capability flags allow;
 * the API still enforces every decision. The score orders candidates only.
 */

import Link from 'next/link';
import { use, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { AdvisorNotice } from '@/components/component-advisor/AdvisorNotice';
import { CheckResultBadge, ConfidenceBadge, LifecycleBadge, RiskBadge } from '@/components/component-advisor/AdvisorBadges';
import { DECISION_LABELS, STATUS_LABELS, TRIGGER_LABELS, formatTimestamp, readableCode } from '@/components/component-advisor/labels';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Dialog } from '@/components/ui/Dialog';
import { PageSpinner } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { useAuth } from '@/hooks/useAuth';
import { useRecommendationDecision } from '@/hooks/useComponentAdvisorMutations';
import { usePermission } from '@/hooks/usePermission';
import { ApiError, getAdvisorCandidateCompatibility, getAdvisorCandidateEvidence, getAdvisorRecommendation } from '@/lib/api';
import type { AdvisorCandidate, AdvisorHistory, AdvisorRecommendation, RecommendationDecision } from '@/types/componentAdvisor';

export default function RecommendationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <RecommendationView recommendationId={Number(id)} />;
}

function RecommendationView({ recommendationId }: { recommendationId: number }) {
  const { activeTenantId } = useAuth();
  const canRead = usePermission('component_advisor:read');
  const query = useQuery({
    queryKey: ['component-advisor-recommendation', recommendationId, activeTenantId],
    queryFn: ({ signal }) => getAdvisorRecommendation(recommendationId, signal),
    enabled: canRead && Number.isSafeInteger(recommendationId),
    retry: false,
  });
  const [evidenceFor, setEvidenceFor] = useState<AdvisorCandidate | null>(null);
  const [pending, setPending] = useState<{ decision: RecommendationDecision; candidate?: AdvisorCandidate } | null>(null);

  if (!canRead) {
    return <><TopBar title="Recommendation" /><div className="p-6"><Alert variant="warning">You do not have permission to view recommendations.</Alert></div></>;
  }
  if (query.isLoading) return <><TopBar title="Recommendation" /><PageSpinner /></>;
  if (query.isError || !query.data) {
    const denied = query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 403);
    return <><TopBar title="Recommendation" /><div className="p-6">{denied ? <AdvisorNotice kind="UNAUTHORIZED_SCOPE" /> : <Alert variant="error">Unable to load this recommendation.</Alert>}</div></>;
  }
  const item = query.data;
  const caps = item.capabilities;
  const candidates = item.candidates ?? [];
  const sameFamily = candidates.filter((c) => c.candidate_kind === 'SAME_FAMILY_VERSION');
  const alternatives = candidates.filter((c) => c.candidate_kind === 'ALTERNATIVE');
  const recommended = candidates.find((c) => c.id === item.review.recommended_candidate_id) ?? null;
  const discovery = item.discovery;

  return (
    <>
      <TopBar title={`Recommendation #${item.id}`} />
      <div className="space-y-4 p-6">
        <Link href={`/component-advisor/components/${item.source.canonical_key}`} className="text-sm text-hcl-blue underline">
          ← {item.source.name} {item.source.version}
        </Link>
        <p className="text-xs text-hcl-muted">
          Advisory only. Accepting records a decision; it never changes a dependency, manifest, source file or SBOM.
          Scores order candidates for review and are not a measure of safety.
        </p>

        <Card>
          <CardHeader><CardTitle>Source component</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{item.source.name} {item.source.version}</span>
              {discovery.source_posture ? <RiskBadge classification={discovery.source_posture.classification} /> : null}
              {discovery.source_posture ? <LifecycleBadge bucket={discovery.source_posture.lifecycle_bucket} /> : null}
              <Badge variant="gray">{STATUS_LABELS[item.status]}</Badge>
            </div>
            <p>Reason: {TRIGGER_LABELS[item.trigger_type]} · Context: {item.context.level === 'SBOM' ? `SBOM #${item.context.sbom_id}` : 'Tenant-wide'} · Evaluated {formatTimestamp(item.evaluated_at)}</p>
            {discovery.source_posture?.actionable_vulnerability_ids?.length ? (
              <p>Actionable: {discovery.source_posture.actionable_vulnerability_ids.join(', ')}</p>
            ) : null}
            {discovery.source_history ? <HistorySummary history={discovery.source_history} /> : null}
            {item.review.last_decision ? (
              <p data-testid="last-decision">Last decision: {DECISION_LABELS[item.review.last_decision]} by {item.review.decided_by} — {item.review.last_decision_reason}</p>
            ) : null}
          </CardContent>
        </Card>

        <DiscoveryNotices item={item} />

        <ActionBar item={item} recommended={recommended} onDecide={(decision) => setPending({ decision, candidate: recommended ?? undefined })} />

        <CandidateSection title="Safer versions of the same component" candidates={sameFamily} item={item}
          onEvidence={setEvidenceFor} onRecommend={caps?.can_recommend ? (c) => setPending({ decision: 'RECOMMEND', candidate: c }) : undefined} />
        <CandidateSection title="Alternative components" candidates={alternatives} item={item}
          emptyNotice={discovery.alternatives_status?.startsWith('INSUFFICIENT_PURPOSE') ? 'INSUFFICIENT_PURPOSE_EVIDENCE' : undefined}
          onEvidence={setEvidenceFor} onRecommend={caps?.can_recommend ? (c) => setPending({ decision: 'RECOMMEND', candidate: c }) : undefined} />
      </div>

      <EvidenceDialog recommendationId={item.id} candidate={evidenceFor} onClose={() => setEvidenceFor(null)} />
      <DecisionDialog item={item} pending={pending} onClose={() => setPending(null)} />
    </>
  );
}

function DiscoveryNotices({ item }: { item: AdvisorRecommendation }) {
  const d = item.discovery;
  return (
    <div className="space-y-2">
      {d.status === 'NO_CANDIDATES_FOUND' ? <AdvisorNotice kind="NO_CANDIDATES_FOUND" /> : null}
      {d.alternatives_status?.endsWith('EXTERNAL_SOURCE_DEGRADED') ? <AdvisorNotice kind="EXTERNAL_SOURCE_UNAVAILABLE" /> : null}
      {d.status === 'DISCOVERY_FAILED' ? <Alert variant="error" title="Discovery failed">{item.evaluation_error}</Alert> : null}
      {d.status === 'SOURCE_NOT_IN_CURRENT_DATASET' ? <Alert variant="warning">The source component is no longer in an active SBOM.</Alert> : null}
    </div>
  );
}

function ActionBar({ item, recommended, onDecide }: { item: AdvisorRecommendation; recommended: AdvisorCandidate | null; onDecide: (d: RecommendationDecision) => void }) {
  const caps = item.capabilities;
  if (!caps) return null;
  const actions: Array<[RecommendationDecision, boolean]> = [
    ['ACCEPT', caps.can_accept], ['REJECT', caps.can_reject], ['DEFER', caps.can_defer],
    ['REQUEST_MORE_EVIDENCE', caps.can_request_evidence], ['CLOSE', caps.can_close],
  ];
  const visible = actions.filter(([, allowed]) => allowed);
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Recommendation decisions">
      {recommended ? <span className="text-sm">Recommended: <strong>{recommended.name} {recommended.version}</strong></span> : null}
      {visible.map(([decision]) => (
        <Button key={decision} size="sm" variant={decision === 'ACCEPT' ? 'primary' : 'outline'} onClick={() => onDecide(decision)}>
          {DECISION_LABELS[decision]}
        </Button>
      ))}
      {!visible.length && !caps.can_recommend ? <span className="text-xs text-hcl-muted">{caps.read_only_reason ?? 'Read only'}</span> : null}
    </div>
  );
}

function HistorySummary({ history }: { history: AdvisorHistory }) {
  if (history.status === 'NO_HISTORY_COVERAGE') {
    return <p className="text-xs">Vulnerability history: no source covers the {history.window_months}-month window.</p>;
  }
  return (
    <p className="text-xs">
      Vulnerability history ({history.coverage.covered_months} of {history.window_months} months covered):{' '}
      {history.disclosed_vulnerability_count} disclosed, {history.critical_high_count} critical/high
      {history.note ? ` — ${history.note}` : ''}
      {history.coverage.gaps.length ? ` · gaps: ${history.coverage.gaps.map(readableCode).join(', ')}` : ''}
    </p>
  );
}

function CandidateSection({ title, candidates, item, onEvidence, onRecommend, emptyNotice }: {
  title: string; candidates: AdvisorCandidate[]; item: AdvisorRecommendation;
  onEvidence: (c: AdvisorCandidate) => void; onRecommend?: (c: AdvisorCandidate) => void;
  emptyNotice?: 'INSUFFICIENT_PURPOSE_EVIDENCE';
}) {
  return (
    <section aria-label={title} className="space-y-2">
      <h2 className="text-sm font-semibold">{title}</h2>
      {!candidates.length ? (emptyNotice ? <AdvisorNotice kind={emptyNotice} /> : <p className="text-xs text-hcl-muted">None proposed.</p>) : (
        <ol className="space-y-3">
          {candidates.map((c) => <CandidateCard key={c.id} c={c} item={item} onEvidence={onEvidence} onRecommend={onRecommend} />)}
        </ol>
      )}
    </section>
  );
}

function CandidateCard({ c, item, onEvidence, onRecommend }: {
  c: AdvisorCandidate; item: AdvisorRecommendation; onEvidence: (c: AdvisorCandidate) => void; onRecommend?: (c: AdvisorCandidate) => void;
}) {
  const posture = c.evaluation.current_posture;
  const compat = c.compatibility;
  const incomplete = (compat.counts?.UNKNOWN ?? 0) > 0;
  const stale = (c.freshness?.stale_flags ?? []).length > 0;
  const canRecommend = onRecommend && !c.blocked && c.confidence !== 'INSUFFICIENT_EVIDENCE';
  return (
    <li>
      <Card>
        <CardContent className="space-y-2 pt-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-hcl-muted">#{c.rank}</span>
            <span className="font-medium">{c.name} {c.version}</span>
            <Badge variant="gray">{c.candidate_kind === 'SAME_FAMILY_VERSION' ? 'Same component, other version' : 'Alternative component'}</Badge>
            <Badge variant="gray">{readableCode(c.source_type)}</Badge>
            <ConfidenceBadge confidence={c.confidence} />
            {posture?.classification ? <RiskBadge classification={posture.classification} /> : <span className="text-xs">Posture not observed in this tenant</span>}
            {c.evaluation.lifecycle ? <LifecycleBadge bucket={c.evaluation.lifecycle.bucket} /> : null}
            {c.blocked ? <CheckResultBadge result="FAIL" blocking /> : null}
            {c.recommended ? <Badge variant="info">Recommended</Badge> : null}
            {c.approved_replacement ? <Badge variant="success">Accepted by reviewer</Badge> : null}
          </div>
          <p className="text-xs">
            Ranking score {c.score ?? '—'} (orders candidates only) · Used by {c.evaluation.adoption?.product_count ?? 0} product(s) in {c.evaluation.adoption?.active_sbom_occurrences ?? 0} active SBOM(s)
            {c.evaluation.license ? ` · License ${c.evaluation.license.candidate?.join(', ') ?? 'unknown'}${c.evaluation.license.changed ? ' (changed)' : ''}` : ''}
          </p>
          {c.history ? <HistorySummary history={c.history} /> : null}
          <p className="text-xs">
            Compatibility: {readableCode(compat.status)}
            {compat.counts ? ` — pass ${compat.counts.PASS}, review ${compat.counts.REVIEW_REQUIRED}, unknown ${compat.counts.UNKNOWN}, fail ${compat.counts.FAIL}` : ''}
            {compat.blocking_checks?.length ? ` · blocked by ${compat.blocking_checks.map(readableCode).join(', ')}` : ''}
          </p>
          {c.blocked ? <Alert variant="error">Blocked by a compatibility check; it cannot be recommended or accepted.</Alert> : null}
          {incomplete && !c.blocked ? <AdvisorNotice kind="INSUFFICIENT_COMPATIBILITY_EVIDENCE" /> : null}
          {stale ? <AdvisorNotice kind="STALE_VULNERABILITY_DATA" /> : null}
          {c.explanation ? <p>{c.explanation.summary}</p> : null}
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <p className="text-xs font-semibold">Reasons</p>
              <ul className="list-disc pl-5 text-xs">{(c.explanation?.reasons.length ? c.explanation.reasons : c.reasons.map((r) => readableCode(r.code))).map((r) => <li key={r}>{r}</li>)}</ul>
            </div>
            <div>
              <p className="text-xs font-semibold">Limitations</p>
              <ul className="list-disc pl-5 text-xs">{(c.explanation?.limitations.length ? c.explanation.limitations : c.limitations.map((l) => readableCode(l.code))).map((l) => <li key={l}>{l}</li>)}</ul>
            </div>
          </div>
          <p className="text-[10px] text-hcl-muted">Evidence: analysis {formatTimestamp(c.freshness?.latest_sbom_analysis_at)} · lifecycle {formatTimestamp(c.freshness?.lifecycle_refreshed_at)} · vulnerability data {formatTimestamp(c.freshness?.vulnerability_source_refreshed_at)}</p>
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => onEvidence(c)} aria-label={`View evidence for ${c.name} ${c.version ?? ''}`}>View evidence</Button>
            {canRecommend && item.status === 'REVIEW_REQUIRED' ? (
              <Button size="sm" variant="outline" onClick={() => onRecommend?.(c)} aria-label={`Recommend ${c.name} ${c.version ?? ''}`}>Recommend</Button>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </li>
  );
}

function EvidenceDialog({ recommendationId, candidate, onClose }: { recommendationId: number; candidate: AdvisorCandidate | null; onClose: () => void }) {
  const { activeTenantId } = useAuth();
  const evidence = useQuery({
    queryKey: ['component-advisor-candidate-evidence', recommendationId, candidate?.id, activeTenantId],
    queryFn: ({ signal }) => getAdvisorCandidateEvidence(recommendationId, candidate!.id, signal),
    enabled: candidate !== null,
  });
  const checks = useQuery({
    queryKey: ['component-advisor-candidate-evidence', recommendationId, candidate?.id, 'checks', activeTenantId],
    queryFn: ({ signal }) => getAdvisorCandidateCompatibility(recommendationId, candidate!.id, signal),
    enabled: candidate !== null,
  });
  return (
    <Dialog open={candidate !== null} onClose={onClose} title={candidate ? `Evidence: ${candidate.name} ${candidate.version ?? ''}` : 'Evidence'} maxWidth="3xl">
      <div className="space-y-4 p-4 text-sm">
        {evidence.isLoading || checks.isLoading ? <p role="status">Loading evidence…</p> : null}
        {evidence.data ? (
          <>
            <p>Ranking score {evidence.data.score} — orders candidates only · Scoring policy {evidence.data.scoring_policy?.label}</p>
            {evidence.data.confidence_basis ? (
              <p>Confidence: {evidence.data.confidence_basis.level} (evidence completeness {Math.round(evidence.data.confidence_basis.completeness * 100)}%)
                {evidence.data.confidence_basis.unknown_material_checks.length ? ` · missing: ${evidence.data.confidence_basis.unknown_material_checks.map(readableCode).join(', ')}` : ''}</p>
            ) : null}
            <Table ariaLabel="Scoring factors">
              <TableHead><tr><Th>Factor</Th><Th>Raw</Th><Th>Normalized</Th><Th>Weight</Th><Th>Contribution</Th><Th>Evidence</Th></tr></TableHead>
              <TableBody>
                {evidence.data.factors.map((f) => (
                  <tr key={f.factor}>
                    <Td>{readableCode(f.factor)}</Td>
                    <Td>{f.raw_value === null || f.raw_value === undefined ? '—' : typeof f.raw_value === 'object' ? JSON.stringify(f.raw_value) : String(f.raw_value)}</Td>
                    <Td>{f.normalized_value ?? `missing (${f.missing_data_treatment?.toLowerCase()})`}</Td>
                    <Td>{f.weight}</Td>
                    <Td>{f.contribution}</Td>
                    <Td>{f.evidence_source}{f.evidence_at ? ` · ${formatTimestamp(f.evidence_at)}` : ''}</Td>
                  </tr>
                ))}
              </TableBody>
            </Table>
          </>
        ) : null}
        {checks.data ? (
          <Table ariaLabel="Compatibility checks">
            <TableHead><tr><Th>Check</Th><Th>Result</Th><Th>Reason</Th><Th>Limitation</Th></tr></TableHead>
            <TableBody>
              {checks.data.items.map((check) => (
                <tr key={check.id}>
                  <Td>{readableCode(check.check_type)}</Td>
                  <Td><CheckResultBadge result={check.result} blocking={check.blocking} /></Td>
                  <Td>{check.reason}</Td>
                  <Td>{check.limitation ? readableCode(check.limitation) : '—'}</Td>
                </tr>
              ))}
            </TableBody>
          </Table>
        ) : null}
      </div>
    </Dialog>
  );
}

function DecisionDialog({ item, pending, onClose }: {
  item: AdvisorRecommendation; pending: { decision: RecommendationDecision; candidate?: AdvisorCandidate } | null; onClose: () => void;
}) {
  const decide = useRecommendationDecision(item.id);
  const [reason, setReason] = useState('');
  const conflict = decide.error instanceof ApiError && decide.error.status === 409;
  const rejected = decide.error instanceof ApiError && decide.error.status !== 409;

  async function submit() {
    if (!pending || !reason.trim()) return;
    await decide.mutateAsync({
      decision: pending.decision, reason: reason.trim(), rowVersion: item.row_version,
      candidateId: pending.decision === 'RECOMMEND' ? pending.candidate?.id : undefined,
    });
    setReason('');
    onClose();
  }

  return (
    <Dialog open={pending !== null} onClose={onClose} title={pending ? DECISION_LABELS[pending.decision] : 'Decision'}>
      <div className="space-y-3 p-4 text-sm">
        {pending?.candidate ? <p>Candidate: <strong>{pending.candidate.name} {pending.candidate.version}</strong></p> : null}
        <label className="block">
          <span className="mb-1 block text-xs font-semibold">Reason (required, recorded in the audit trail)</span>
          <textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={3} required
            className="w-full rounded border border-border p-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue" />
        </label>
        {conflict ? <Alert variant="warning">This recommendation changed since you opened it. It has been reloaded; review it and try again.</Alert> : null}
        {rejected ? <Alert variant="error">The decision was refused. Your role or the candidate may not allow it.</Alert> : null}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={!reason.trim() || decide.isPending}>{decide.isPending ? 'Saving…' : 'Confirm'}</Button>
        </div>
      </div>
    </Dialog>
  );
}
