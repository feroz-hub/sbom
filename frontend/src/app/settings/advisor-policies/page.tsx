'use client';

import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { TopBar } from '@/components/layout/TopBar';
import { ApiError } from '@/lib/api';
import { getAdvisorPolicy, getAdvisorPolicyHistory, publishAdvisorPolicy, type AdvisorPolicyKind, type AdvisorPolicyState, type AdvisorPolicyStatus } from '@/lib/advisorPolicyApi';

const definitions: { kind: AdvisorPolicyKind; title: string; description: string; example: Record<string, unknown> }[] = [
  { kind: 'accepted-risk', title: 'Accepted risk', description: 'Accept only Low or Medium actionable risk. Critical and High vulnerabilities can never be accepted. Optional rules restrict CVSS, vulnerability count, VEX status, lifecycle and analysis age.', example: { max_actionable_severity: 'MEDIUM', max_cvss_score: 6.9, max_actionable_vulnerabilities: 3, max_analysis_age_days: 30 } },
  { kind: 'trust', title: 'Trust', description: 'Require allowed classifications and lifecycle states. Optional license allow/deny lists, evidence age and minimum product adoption further restrict trust.', example: { allowed_classifications: ['NO_KNOWN_ACTIONABLE_VULNERABILITIES', 'LOW'], allowed_lifecycle: ['SUPPORTED'], allowed_licenses: ['MIT', 'Apache-2.0'], max_evidence_age_days: 90, require_no_review_reasons: true } },
  { kind: 'scoring', title: 'Recommendation scoring', description: 'Weights order recommendation candidates; they do not override security gates. Weights must sum to 1. Missing data can be PENALIZE or EXCLUDE; history window is 6–120 months and stale threshold is 1–3650 days.', example: { weights: { current_risk: 0.30, lifecycle: 0.20, vulnerability_trend: 0.15, compatibility: 0.15, maintenance: 0.08, license: 0.05, tenant_adoption: 0.05, evidence_freshness: 0.02 }, missing_data: 'PENALIZE', history_window_months: 24, stale_after_days: 90 } },
];
const inputClass = 'w-full rounded border border-border-subtle bg-surface p-2';

function PolicyEditor({ tenantId, definition, state, canUpdate }: { tenantId: number; definition: typeof definitions[number]; state: AdvisorPolicyState; canUpdate: boolean }) {
  const client = useQueryClient();
  const [status, setStatus] = useState<AdvisorPolicyStatus>(state.tenant_override?.status ?? 'INHERIT');
  const [rules, setRules] = useState(JSON.stringify(state.tenant_override?.status === 'ACTIVE' ? state.tenant_override.rules : state.effective?.rules ?? definition.example, null, 2));
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  useEffect(() => {
    setStatus(state.tenant_override?.status ?? 'INHERIT');
    setRules(JSON.stringify(state.tenant_override?.status === 'ACTIVE' ? state.tenant_override.rules : state.effective?.rules ?? definition.example, null, 2));
    setConflict(false); setError('');
  }, [state, definition]);
  const history = useQuery({ queryKey: ['advisor-policy-history', tenantId, definition.kind], queryFn: () => getAdvisorPolicyHistory(tenantId, definition.kind), retry: false });
  async function publish(event: React.FormEvent) {
    event.preventDefault(); setError(''); setSaved(false);
    let parsed: Record<string, unknown> | null = null;
    try {
      if (status === 'ACTIVE') {
        parsed = JSON.parse(rules);
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('Rules must be a JSON object.');
      }
      if (!reason.trim()) throw new Error('Enter a reason for this change.');
    } catch (err) { setError(err instanceof Error ? err.message : 'Invalid rules.'); return; }
    setSaving(true);
    try {
      const result = await publishAdvisorPolicy(tenantId, definition.kind, { status, rules: parsed, reason: reason.trim(), row_version: state.row_version });
      setReason(''); setSaved(true);
      client.setQueryData(['advisor-policy', tenantId, definition.kind], result);
      await client.invalidateQueries({ queryKey: ['advisor-policy-history', tenantId, definition.kind] });
      await client.invalidateQueries({ predicate: query => String(query.queryKey[0]).startsWith('component-advisor-') });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) { setConflict(true); setError('Another administrator changed this policy. Reload the latest policy before publishing again.'); }
      else setError(err instanceof Error ? err.message : 'Unable to publish policy.');
    } finally { setSaving(false); }
  }
  return <div className="space-y-4">
    <p>{state.effective ? `Effective: ${state.effective.scope.toLowerCase()} policy v${state.effective.version}` : definition.kind === 'scoring' ? 'Effective: built-in scoring defaults' : 'Policy not configured'}</p>
    {state.effective && <details><summary>Effective rules</summary><pre className="overflow-auto text-sm">{JSON.stringify(state.effective.rules, null, 2)}</pre></details>}
    <form onSubmit={publish} className="space-y-3">
      <fieldset disabled={!canUpdate || saving || conflict} className="space-y-3">
        <label className="block">Policy mode<select aria-label={`${definition.title} policy mode`} className={inputClass} value={status} onChange={event => setStatus(event.target.value as AdvisorPolicyStatus)}><option value="INHERIT">Inherit platform default</option><option value="ACTIVE">Use tenant policy</option><option value="DISABLED">Disable policy for this tenant</option></select></label>
        <p className="text-sm text-hcl-muted">Inherit uses an available platform default. Disable blocks inheritance. Scoring falls back to built-in defaults when no policy applies.</p>
        {status === 'ACTIVE' && <label className="block">Rules (JSON)<textarea aria-label={`${definition.title} rules`} className={`${inputClass} font-mono text-sm`} rows={12} value={rules} onChange={event => setRules(event.target.value)} spellCheck={false} /></label>}
        {canUpdate && <><label className="block">Reason for change<input aria-label={`${definition.title} reason`} className={inputClass} required maxLength={2000} value={reason} onChange={event => setReason(event.target.value)} /></label><button className="rounded bg-primary px-4 py-2 text-white" type="submit">{saving ? 'Publishing…' : 'Publish policy version'}</button></>}
      </fieldset>
    </form>
    {!canUpdate && <p>Read-only access. A Tenant Admin can publish policy changes.</p>}
    {error && <p role="alert">{error}</p>}
    {conflict && <button onClick={() => client.invalidateQueries({ queryKey: ['advisor-policy', tenantId, definition.kind] })}>Reload latest policy (discard draft)</button>}
    {saved && <p role="status">Policy version published.</p>}
    <details><summary>Version history</summary>{history.isPending ? <p>Loading history…</p> : history.isError ? <p role="alert">Unable to load history.</p> : history.data.items.length === 0 ? <p>No tenant versions published.</p> : <ul className="space-y-3">{history.data.items.map(version => <li key={version.id}><p>v{version.version} · {version.status} · {version.created_at} · {version.created_by}</p><p>{version.reason}</p><pre className="overflow-auto text-xs">{JSON.stringify(version.rules, null, 2)}</pre></li>)}</ul>}</details>
  </div>;
}
function PolicyCard({ tenantId, definition, canUpdate }: { tenantId: number; definition: typeof definitions[number]; canUpdate: boolean }) {
  const query = useQuery({ queryKey: ['advisor-policy', tenantId, definition.kind], queryFn: () => getAdvisorPolicy(tenantId, definition.kind), retry: false });
  return <section className="space-y-3 rounded-lg border border-border-subtle bg-surface p-5"><h2 className="text-lg font-semibold">{definition.title}</h2><p>{definition.description}</p>{query.isPending ? <p>Loading policy…</p> : query.isError ? <><p role="alert">Unable to load policy: {query.error.message}</p><button onClick={() => query.refetch()}>Retry</button></> : <PolicyEditor tenantId={tenantId} definition={definition} state={query.data} canUpdate={canUpdate} />}</section>;
}
export default function AdvisorPoliciesPage() {
  const { activeTenantId, activeTenant, hasPermission, isLoading, isTenantContextLoading } = useAuth();
  if (isLoading || isTenantContextLoading) return <p>Verifying configuration access…</p>;
  if (!activeTenantId || !hasPermission('tenant:advisor-policy:read')) return <p role="alert">Policy configuration access is not permitted in this context.</p>;
  return <div className="flex flex-1 flex-col"><TopBar title="Component Advisor Policies" subtitle={`Configuration for ${activeTenant?.name ?? 'this tenant'}`} /><main className="mx-auto w-full max-w-4xl space-y-5 p-6"><p>Manage policies for {activeTenant?.name ?? 'the active tenant'}. Every published change creates a new version and preserves history.</p>{definitions.map(definition => <PolicyCard key={`${activeTenantId}:${definition.kind}`} tenantId={Number(activeTenantId)} definition={definition} canUpdate={hasPermission('tenant:advisor-policy:update')} />)}</main></div>;
}
