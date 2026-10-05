'use client';

/**
 * Secure Component Advisor — component version detail (spec Step 9;
 * FR-SCA-001/009/010/011, US-SCA-08/09).
 *
 * Identity, purpose with provenance (AI-assisted metadata visibly flagged),
 * risk, lifecycle, licenses, tenant adoption, freshness and the open
 * recommendation, plus "Find safer options" where the user may run one. The
 * backend validates the trigger against current evidence and returns the
 * existing open item instead of a duplicate.
 */

import Link from 'next/link';
import { Suspense, use, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter, useSearchParams } from 'next/navigation';
import { TopBar } from '@/components/layout/TopBar';
import { AdvisorNotice } from '@/components/component-advisor/AdvisorNotice';
import { LifecycleBadge, ProvenanceBadge, RiskBadge } from '@/components/component-advisor/AdvisorBadges';
import { STATUS_LABELS, TRIGGER_LABELS, formatTimestamp, readableCode } from '@/components/component-advisor/labels';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { PageSpinner } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { useAuth } from '@/hooks/useAuth';
import { useCreateRecommendation } from '@/hooks/useComponentAdvisorMutations';
import { usePermission } from '@/hooks/usePermission';
import { ApiError, getAdvisorComponent } from '@/lib/api';
import type { AdvisorComponentDetail, AdvisorPurposeField, RecommendationTrigger } from '@/types/componentAdvisor';

function positiveOrNull(value: string | null): number | null {
  const id = Number(value);
  return value && Number.isSafeInteger(id) && id > 0 ? id : null;
}

export default function ComponentDetailPage({ params }: { params: Promise<{ key: string }> }) {
  const { key } = use(params);
  return (
    <Suspense fallback={<PageSpinner />}>
      <ComponentDetail canonicalKey={decodeURIComponent(key)} />
    </Suspense>
  );
}

function ComponentDetail({ canonicalKey }: { canonicalKey: string }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { activeTenantId } = useAuth();
  const canRead = usePermission('component_advisor:read');
  const canRun = usePermission('component_advisor:recommendation:create');
  const scope = {
    project_id: positiveOrNull(searchParams.get('project_id')),
    product_id: positiveOrNull(searchParams.get('product_id')),
    sbom_id: positiveOrNull(searchParams.get('sbom_id')),
  };
  const query = useQuery({
    queryKey: ['component-advisor-component', activeTenantId, canonicalKey, scope],
    queryFn: ({ signal }) => getAdvisorComponent(canonicalKey, scope, signal),
    enabled: canRead,
    retry: false,
  });
  const create = useCreateRecommendation();
  const [trigger, setTrigger] = useState<RecommendationTrigger | ''>('');
  const [alreadyOpen, setAlreadyOpen] = useState<number | null>(null);

  if (!canRead) {
    return <><TopBar title="Component" /><div className="p-6"><Alert variant="warning">You do not have permission to view the Secure Component Advisor.</Alert></div></>;
  }
  if (query.isLoading) return <><TopBar title="Component" /><PageSpinner /></>;
  if (query.isError) {
    const denied = query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 403);
    return (
      <><TopBar title="Component" />
        <div className="space-y-3 p-6">
          {denied ? <AdvisorNotice kind="UNAUTHORIZED_SCOPE" /> : <Alert variant="error">Unable to load this component.</Alert>}
          <Link href="/component-advisor" className="text-sm text-hcl-blue underline">Back to Secure Component Advisor</Link>
        </div>
      </>
    );
  }
  const c = query.data as AdvisorComponentDetail;
  const triggers = c.eligible_triggers ?? [];
  const chosen = (trigger || triggers.find((t) => t !== 'MANUAL') || 'MANUAL') as RecommendationTrigger;
  const openItem = c.recommendation.id ? c.recommendation : null;

  async function findSaferOptions() {
    const item = await create.mutateAsync({ canonicalKey, trigger: chosen, scope });
    if (item.created === false) setAlreadyOpen(item.id);
    router.push(`/component-advisor/recommendations/${item.id}`);
  }

  return (
    <>
      <TopBar title={`${c.name} ${c.version ?? ''}`.trim()} />
      <div className="space-y-4 p-6">
        <Link href="/component-advisor" className="text-sm text-hcl-blue underline">← Secure Component Advisor</Link>
        <div className="flex flex-wrap items-center gap-2">
          <RiskBadge classification={c.risk.classification} />
          <LifecycleBadge bucket={c.lifecycle.bucket} />
          {c.trust.status === 'TRUSTED_BY_POLICY' ? <span className="text-xs font-medium">Trusted by policy (v{c.trust.policy_version_id})</span> : null}
        </div>

        <Card>
          <CardHeader><CardTitle>Recommendation</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {openItem ? (
              <AdvisorNotice kind="RECOMMENDATION_ALREADY_OPEN">
                <Link className="text-hcl-blue underline" href={`/component-advisor/recommendations/${openItem.id}`}>
                  Open recommendation #{openItem.id} ({STATUS_LABELS[openItem.status]})
                </Link>
              </AdvisorNotice>
            ) : <p className="text-sm">{STATUS_LABELS[c.recommendation.status]}</p>}
            {alreadyOpen ? <AdvisorNotice kind="RECOMMENDATION_ALREADY_OPEN" /> : null}
            {canRun && !openItem ? (
              <div className="flex flex-wrap items-end gap-3">
                <Select label="Reason" value={chosen} onChange={(event) => setTrigger(event.target.value as RecommendationTrigger)}>
                  {triggers.map((t) => <option key={t} value={t}>{TRIGGER_LABELS[t]}</option>)}
                </Select>
                <Button onClick={findSaferOptions} disabled={create.isPending}>
                  {create.isPending ? 'Evaluating…' : 'Find safer options'}
                </Button>
              </div>
            ) : null}
            {create.isError ? <Alert variant="error">Could not start the recommendation. The evidence may have changed; reload and try again.</Alert> : null}
            <p className="text-xs text-hcl-muted">Recommendations are advisory and need human review. Nothing is upgraded or replaced automatically.</p>
          </CardContent>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader><CardTitle>Identity</CardTitle></CardHeader>
            <CardContent>
              <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-hcl-muted">Name</dt><dd>{c.name}</dd>
                <dt className="text-hcl-muted">Version</dt><dd>{c.version ?? '—'}</dd>
                <dt className="text-hcl-muted">Supplier</dt><dd>{c.supplier ?? '—'}</dd>
                <dt className="text-hcl-muted">Ecosystem</dt><dd>{c.ecosystem ?? '—'}</dd>
                <dt className="text-hcl-muted">PURL</dt><dd className="break-all">{c.purl ?? '—'}</dd>
                <dt className="text-hcl-muted">CPE</dt><dd className="break-all">{c.cpe ?? '—'}</dd>
                <dt className="text-hcl-muted">Identity</dt><dd>{readableCode(c.identity.basis)} · {c.identity.confidence.toLowerCase()} confidence</dd>
                <dt className="text-hcl-muted">Licenses</dt><dd>{c.licenses.length ? c.licenses.join(', ') : 'Not declared'}</dd>
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Purpose</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {c.purpose.status === 'NOT_AVAILABLE' ? <AdvisorNotice kind="INSUFFICIENT_PURPOSE_EVIDENCE" /> : (
                <dl className="space-y-2 text-sm">
                  <PurposeRow label="Functional description" field={c.purpose.functional_description} />
                  <PurposeRow label="Primary use case" field={c.purpose.primary_use_case} />
                  <PurposeRow label="Technology category" field={c.purpose.technology_category} />
                </dl>
              )}
              {c.purpose.ai_assisted ? <p className="text-xs text-hcl-muted">AI-assisted fields are suggestions with provenance, not authoritative metadata.</p> : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Risk</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>{c.risk.actionable_vulnerability_count} actionable / {c.risk.non_actionable_vulnerability_count} non-actionable (fixed or not affected) vulnerabilities</p>
              <p>Critical {c.risk.actionable_severity_counts.critical} · High {c.risk.actionable_severity_counts.high} · Medium {c.risk.actionable_severity_counts.medium} · Low {c.risk.actionable_severity_counts.low} · Unknown {c.risk.actionable_severity_counts.unknown}</p>
              <p>Highest CVSS {c.risk.cvss.max_score ?? '—'}{c.risk.cvss.vector ? ` (${c.risk.cvss.vector})` : ''}</p>
              {c.risk.review_reasons.length ? (
                <div><p className="font-medium">Needs review</p><ul className="list-disc pl-5">{c.risk.review_reasons.map((r) => <li key={r}>{readableCode(r)}</li>)}</ul></div>
              ) : null}
              {c.risk.accepted_risk ? (
                <div>
                  <p className="font-medium">Accepted-risk policy v{c.risk.accepted_risk.policy_version_id}: {c.risk.accepted_risk.satisfied ? 'satisfied' : 'not satisfied'}</p>
                  <ul className="list-disc pl-5 text-xs">{c.risk.accepted_risk.criteria.map((item) => <li key={item.criterion}>{item.passed ? 'Passed' : 'Failed'}: {item.detail}</li>)}</ul>
                </div>
              ) : <AdvisorNotice kind="POLICY_NOT_CONFIGURED" />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Lifecycle and freshness</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              {c.lifecycle.bucket === 'UNKNOWN' ? <AdvisorNotice kind="LIFECYCLE_EVIDENCE_UNAVAILABLE" /> : (
                <p>{c.lifecycle.status}{c.lifecycle.effective_date ? ` since ${c.lifecycle.effective_date}` : ''}{c.lifecycle.source ? ` · source ${c.lifecycle.source}` : ''}</p>
              )}
              <p>Latest analysis: {formatTimestamp(c.freshness.latest_analysis_at)} ({c.freshness.analysed_occurrences}/{c.freshness.total_occurrences} occurrences analysed)</p>
              <p>Lifecycle checked: {formatTimestamp(c.freshness.lifecycle_checked_at)}{c.freshness.lifecycle_is_stale ? ' · stale' : ''}</p>
              <p>Vulnerability data refreshed: {formatTimestamp(c.meta.freshness.vulnerability_source_refreshed_at)}</p>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader><CardTitle>Adoption in this tenant</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-xs text-hcl-muted">Adoption is contextual evidence only — not proof of compatibility or security.</p>
            {c.adoption.active_sbom_occurrences === 0 ? <AdvisorNotice kind="NO_ACTIVE_SBOM_OCCURRENCES" /> : (
              <p>{c.adoption.active_sbom_occurrences} active SBOM occurrence(s) · Products: {c.adoption.products.map((p) => p.name ?? `#${p.id}`).join(', ') || '—'} · Projects: {c.adoption.projects.map((p) => p.name ?? `#${p.id}`).join(', ') || '—'}</p>
            )}
            <Table ariaLabel="Observed versions of this component">
              <TableHead><tr><Th>Version</Th><Th>Risk</Th><Th>Lifecycle</Th><Th>Licenses</Th><Th>Occurrences</Th><Th>Products</Th></tr></TableHead>
              <TableBody>
                {c.adoption.observed_versions.map((v) => (
                  <tr key={v.canonical_key} aria-current={v.is_this_version ? 'true' : undefined}>
                    <Td>{v.is_this_version ? <strong>{v.version} (this version)</strong> : (
                      <Link className="text-hcl-blue underline" href={`/component-advisor/components/${v.canonical_key}`}>{v.version}</Link>
                    )}</Td>
                    <Td><RiskBadge classification={v.classification} /></Td>
                    <Td><LifecycleBadge bucket={v.lifecycle_bucket} /></Td>
                    <Td>{v.licenses.join(', ') || '—'}</Td>
                    <Td>{v.active_sbom_occurrences}</Td>
                    <Td>{v.product_count}</Td>
                  </tr>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function PurposeRow({ label, field }: { label: string; field: AdvisorPurposeField | null }) {
  return (
    <div>
      <dt className="text-xs text-hcl-muted">{label}</dt>
      <dd className="flex flex-wrap items-center gap-2">
        {field ? <><span>{field.value}</span><ProvenanceBadge field={field} /></> : <span className="text-hcl-muted">Not available</span>}
      </dd>
    </div>
  );
}
