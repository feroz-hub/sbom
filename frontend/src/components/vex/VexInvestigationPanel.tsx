'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { resolveVexInvestigationComponent, setVexInvestigationAssignment } from '@/lib/api';
import { invalidateVexSurfaces } from '@/lib/queryInvalidation';
import type { VexInvestigationDetail } from '@/types';
import { VexDecisionEditor } from './VexDecisionEditor';

export function VexInvestigationPanel({
  detail,
  onSaved,
  onConflict,
}: {
  detail: VexInvestigationDetail;
  onSaved: () => void;
  onConflict: () => void;
}) {
  const [formError, setFormError] = useState<string | null>(null);
  const [assignee, setAssignee] = useState(detail.internal_decision.assigned_to ?? '');
  const [componentId, setComponentId] = useState('');
  const [assigneeSearch, setAssigneeSearch] = useState('');
  const access = detail.capabilities;
  const ownerRole = access?.owner.roles.includes('SECURITY_ANALYST') ? 'Security Analyst' : access?.owner.roles.includes('DEVELOPER') ? 'Developer' : null;
  const ownerLabel = access?.owner.is_self ? `${access.owner.label} (You)` : `${access?.owner.label ?? 'Unassigned'}${ownerRole ? ` — ${ownerRole}` : ''}`;
  const analystCandidates = access?.eligible_roles.includes('SECURITY_ANALYST');
  const queryClient = useQueryClient();
  useEffect(() => {
    setAssignee(detail.internal_decision.assigned_to ?? '');
    setFormError(null);
  }, [detail.id, detail.row_version, detail.internal_decision.assigned_to]);

  const assignment = useMutation({
    mutationFn: (selected: string | null) =>
      setVexInvestigationAssignment(detail.id, {
        assigned_to: selected,
        row_version: detail.row_version,
        reason: selected ? 'Assignment updated' : 'Assignment removed',
      }),
    onSuccess: () => {
      invalidateVexSurfaces(queryClient);
      onSaved();
    },
    onError: (error: unknown) => {
      if ((error as { status?: number })?.status === 409) return onConflict();
      setFormError(error instanceof Error ? error.message : 'Could not save the assignment.');
    },
  });

  const mapping = useMutation({
    mutationFn: () =>
      resolveVexInvestigationComponent(detail.id, {
        component_id: Number(componentId),
        row_version: detail.row_version,
        reason: `Bound to component ${componentId} by analyst review`,
      }),
    onSuccess: () => {
      invalidateVexSurfaces(queryClient);
      onSaved();
    },
    onError: (error: unknown) => {
      if ((error as { status?: number })?.status === 409) return onConflict();
      setFormError(error instanceof Error ? error.message : 'Could not bind the component.');
    },
  });

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-3">
        <Section title="Analyzer Evidence">
          <Row label="Detection" value={detail.analyzer_evidence.detection_state} />
          <Row label="Sources" value={detail.analyzer_evidence.sources.join(', ')} />
          <Row label="Run" value={detail.analyzer_evidence.analysis_run_id} />
          <Row label="Match" value={detail.analyzer_evidence.match_strategy} />
          <Row label="First seen" value={detail.analyzer_evidence.first_seen_at} />
          <Row label="Last seen" value={detail.analyzer_evidence.last_seen_at} />
        </Section>

        <Section title="Imported VEX">
          {detail.imported_vex.length === 0 ? (
            <p className="text-xs text-hcl-muted">No imported assertions.</p>
          ) : (
            detail.imported_vex.map((assertion) => (
              <div key={assertion.statement_id} className="mb-2 border-b border-gray-100 pb-2 last:border-0">
                <div className="text-xs font-medium">
                  {assertion.author ?? 'Unknown source'}
                  {assertion.is_effective ? <Badge variant="info">effective</Badge> : null}
                  {assertion.version_applicable === false ? (
                    <Badge variant="gray">not applicable</Badge>
                  ) : null}
                  {assertion.superseded ? <Badge variant="gray">superseded</Badge> : null}
                </div>
                <Row label="Native" value={assertion.source_status} />
                <Row label="Normalized" value={assertion.normalized_status} />
                <Row label="Format" value={assertion.source_format} />
                <Row label="Justification" value={assertion.justification} />
                <Row label="Impact" value={assertion.impact_statement} />
                <Row label="Action" value={assertion.action_statement} />
                <Row label="Mitigation" value={assertion.mitigation} />
                <Row label="Fixed version" value={assertion.fixed_version} />
                <Row label="Evidence" value={assertion.evidence_url} />
                <Row label="Asserted" value={assertion.asserted_at} />
                <Row label="Document" value={assertion.source_document_id} />
                <Row label="Document version" value={assertion.source_document_version} />
              </div>
            ))
          )}
        </Section>

        <Section title="Internal Decision">
          <Row label="Status" value={detail.internal_decision.effective_status} />
          <Row label="Reviewer" value={detail.internal_decision.reviewer} />
          <Row label="Assignee" value={ownerLabel} />
          <Row label="Reason" value={detail.internal_decision.reason} />
          <Row label="Justification" value={detail.internal_decision.justification} />
          <Row label="Impact" value={detail.internal_decision.impact_statement} />
          <Row label="Action" value={detail.internal_decision.action_statement} />
          <Row label="Evidence" value={detail.internal_decision.evidence_url} />
          <Row label="Fixed version" value={detail.internal_decision.fixed_version} />
          <Row label="Mitigation" value={detail.internal_decision.mitigation} />
          <Row label="Updated" value={detail.internal_decision.updated_at} />
        </Section>
      </div>

      <div>
        <Section title="History">
          {detail.history.length === 0 ? (
            <p className="text-xs text-hcl-muted">No recorded history.</p>
          ) : (
            detail.history.map((entry, index) => (
              <div key={`${entry.at}-${index}`} className="text-xs">
                <span className="text-hcl-muted">{entry.at ?? '—'}</span> · {entry.kind} ·{' '}
                {entry.summary ?? entry.new_status}{entry.kind === 'decision' && entry.new_status ? ` · ${entry.previous_status ?? 'No decision'} → ${entry.new_status}` : ''}{entry.actor ? ` · by ${entry.actor}` : ''}
              </div>
            ))
          )}
        </Section>
      </div>

      <Section title={access?.can_assign ? 'Ownership & assignment' : 'Ownership'}>
          <Row label="Assigned to" value={ownerLabel} />
          {access?.owner.id && !access.owner.active ? <p className="text-xs text-hcl-muted">Assigned user is no longer active</p> : null}
          <div className="grid gap-2 md:grid-cols-2">
            {access?.can_assign ? <>
              <Input label="Search assignees" value={assigneeSearch} onChange={(event) => setAssigneeSearch(event.target.value)} placeholder="Search by name" />
              <Select label="Assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)}>
                <option value="">{analystCandidates ? 'Select Security Analyst or Developer' : 'Select Developer'}</option>
                {['SECURITY_ANALYST', 'DEVELOPER'].filter(role => access.eligible_roles.includes(role)).map(role => (
                  <optgroup key={role} label={role === 'SECURITY_ANALYST' ? 'Security Analysts' : 'Developers'}>
                    {access.candidates.filter(candidate => (candidate.roles.includes('SECURITY_ANALYST') ? role === 'SECURITY_ANALYST' : role === 'DEVELOPER') && candidate.label.toLowerCase().includes(assigneeSearch.toLowerCase())).map(candidate => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
                  </optgroup>
                ))}
              </Select>
              <p className="text-xs text-hcl-muted">{analystCandidates ? 'Assign this investigation to a Security Analyst or Developer in this tenant.' : 'Delegate this investigation to a Developer in this tenant.'}</p>
              <div className="flex gap-2">
                <Button variant="ghost" disabled={assignment.isPending || !access.can_unassign || !access.owner.id} onClick={() => assignment.mutate(null)}>Unassign</Button>
                <Button disabled={assignment.isPending || !assignee || !access.candidates.some(candidate => candidate.id === assignee)} onClick={() => assignment.mutate(assignee)}>{assignment.isPending ? 'Saving...' : 'Save assignment'}</Button>
              </div>
            </> : null}
            {access?.can_map && detail.reconciliation_status === 'UNRESOLVED_MAPPING' ? (
              <>
                <Input
                  value={componentId}
                  onChange={(e) => setComponentId(e.target.value)}
                  placeholder="Component ID to bind"
                  aria-label="Component ID"
                />
                <Button
                  variant="ghost"
                  disabled={mapping.isPending || !componentId.trim()}
                  onClick={() => mapping.mutate()}
                >
                  {mapping.isPending ? 'Binding...' : 'Bind to component'}
                </Button>
              </>
            ) : null}
          </div>
          {access?.can_map && detail.reconciliation_status === 'UNRESOLVED_MAPPING' ? (
            <p className="mt-2 text-[11px] text-hcl-muted">
              The matcher found several equally weak candidates and refused to guess.
              Binding re-runs reconciliation for this context.
            </p>
          ) : null}
          {formError ? <Alert variant="error">{formError}</Alert> : null}
        </Section>

      <Section title="Record a decision">
        {/* The shared editor — the same component the SBOM page hosts, so the
            fields and validation cannot drift between the two entry points. */}
        <VexDecisionEditor
          sbomId={detail.sbom_id}
          componentId={detail.component.component_id ?? 0}
          componentLabel={
            detail.component.name
              ? `${detail.component.name}${detail.component.version ? ` ${detail.component.version}` : ''}`
              : undefined
          }
          vulnerabilityId={detail.vulnerability.canonical_vulnerability_id}
          investigation={detail}
          mode="full"
          canWrite={access?.can_update ?? false}
          onSaved={onSaved}
          onConflict={onConflict}
        />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 p-3 dark:border-gray-800">
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">{title}</h3>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="flex justify-between gap-3 text-xs">
      <span className="text-hcl-muted">{label}</span>
      <span className="min-w-0 break-words text-right">{value === null || value === undefined || value === '' ? '—' : value}</span>
    </div>
  );
}
