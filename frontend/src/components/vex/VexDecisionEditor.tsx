'use client';

/**
 * The one VEX decision editor, hosted by both entry points.
 *
 * Before this, the SBOM page and the investigation queue each had their own
 * form, their own validation and their own idea of what a decision contains.
 * They had already drifted: the SBOM form offered a fifth `unknown` status the
 * spec forbids as a determination (section 8) and had no optimistic
 * concurrency at all, so two analysts editing from that page silently
 * overwrote each other.
 *
 * Component and vulnerability are always read-only context here. When the
 * editor is opened from a row, the pair is already known, and re-offering the
 * pickers only creates a chance to save against the wrong one.
 */

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { overrideVexStatement, setVexInvestigationDecision } from '@/lib/api';
import { invalidateVexSurfaces } from '@/lib/queryInvalidation';
import type { VexEffectiveStatus, VexInvestigationDetail } from '@/types';
import {
  EMPTY_DRAFT,
  FIELD_GUIDANCE,
  hasErrors,
  validateVexDecision,
  type VexDecisionDraft,
  type VexDecisionErrors,
} from './vexDecisionValidation';

/**
 * The four canonical statuses (VEX-STAT-001). `unknown` is deliberately
 * absent: spec section 8 makes it source evidence only, never a decision an
 * analyst records.
 */
const STATUS_OPTIONS: Array<{ value: VexEffectiveStatus; label: string }> = [
  { value: 'AFFECTED', label: 'Affected' },
  { value: 'NOT_AFFECTED', label: 'Not affected' },
  { value: 'FIXED', label: 'Fixed' },
  { value: 'UNDER_INVESTIGATION', label: 'Under investigation' },
];

export interface VexDecisionEditorProps {
  sbomId: number;
  componentId: number;
  componentLabel?: string;
  vulnerabilityId: string;
  /** Present when a reconciled context exists: unlocks evidence and row_version. */
  investigation?: VexInvestigationDetail | null;
  /** 'full' is hosted beside the evidence panels; 'compact' stands alone. */
  mode?: 'full' | 'compact';
  canWrite: boolean;
  onSaved?: () => void;
  /** Someone else saved first; the host should refetch and re-present. */
  onConflict?: () => void;
  onCancel?: () => void;
}

function draftFromInvestigation(
  investigation: VexInvestigationDetail | null | undefined,
): VexDecisionDraft {
  if (!investigation) return EMPTY_DRAFT;
  const decision = investigation.internal_decision;
  return {
    status: (investigation.effective_status as VexEffectiveStatus) ?? 'UNDER_INVESTIGATION',
    reason: '', // Never prefilled: each decision states its own reason.
    justification: decision.justification ?? '',
    impactStatement: decision.impact_statement ?? '',
    actionStatement: decision.action_statement ?? '',
    mitigation: '',
    fixedVersion: '',
    evidenceUrl: decision.evidence_url ?? '',
  };
}

export function VexDecisionEditor({
  sbomId,
  componentId,
  componentLabel,
  vulnerabilityId,
  investigation,
  mode = 'compact',
  canWrite,
  onSaved,
  onConflict,
  onCancel,
}: VexDecisionEditorProps) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<VexDecisionDraft>(() => draftFromInvestigation(investigation));
  const [errors, setErrors] = useState<VexDecisionErrors>({});
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Re-seed when the host swaps to a different pair or the context arrives.
  useEffect(() => {
    setDraft(draftFromInvestigation(investigation));
    setErrors({});
    setSubmitError(null);
  }, [investigation, componentId, vulnerabilityId]);

  const guidance = FIELD_GUIDANCE[draft.status];
  const isEmphasised = useMemo(
    () => (field: keyof VexDecisionDraft) => guidance.emphasised.includes(field),
    [guidance],
  );

  function set<K extends keyof VexDecisionDraft>(field: K, value: VexDecisionDraft[K]) {
    setDraft((current) => ({ ...current, [field]: value }));
    // Clear a field's error as soon as the analyst edits it; re-validated on save.
    setErrors((current) => (current[field] ? { ...current, [field]: undefined } : current));
  }

  const save = useMutation({
    mutationFn: async () => {
      const text = (value: string) => value.trim() || undefined;

      // Two save paths, one rule: use the context when there is one.
      //
      // With an investigation we go through the decision endpoint, which
      // carries row_version and rejects a stale write. Without one — a CVE no
      // scanner found and no document asserted — there is no context and
      // nothing to conflict with yet; the override creates the statement, and
      // reconciliation then creates the context, so every later edit takes the
      // first path. Both endpoints reach the same apply_vex_override service.
      if (investigation) {
        return setVexInvestigationDecision(investigation.id, {
          status: draft.status,
          row_version: investigation.row_version,
          reason: draft.reason.trim(),
          justification: text(draft.justification),
          impact_statement: text(draft.impactStatement),
          action_statement: text(draft.actionStatement),
          mitigation: text(draft.mitigation),
          fixed_version: text(draft.fixedVersion),
          evidence_url: text(draft.evidenceUrl),
        });
      }
      return overrideVexStatement(
        componentId,
        vulnerabilityId.trim(),
        {
          status: draft.status.toLowerCase() as never,
          reason: draft.reason.trim(),
          justification: text(draft.justification) ?? null,
          impact_statement: text(draft.impactStatement) ?? null,
          action_statement: text(draft.actionStatement) ?? null,
          mitigation: text(draft.mitigation) ?? null,
          fixed_version: text(draft.fixedVersion) ?? null,
          evidence_url: text(draft.evidenceUrl) ?? null,
        },
        undefined,
        sbomId,
      );
    },
    onSuccess: () => {
      setSubmitError(null);
      invalidateVexSurfaces(queryClient, sbomId);
      onSaved?.();
    },
    onError: (error: unknown) => {
      if ((error as { status?: number })?.status === 409) {
        onConflict?.();
        return;
      }
      setSubmitError(error instanceof Error ? error.message : 'Could not save the decision.');
    },
  });

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const found = validateVexDecision(draft);
    setErrors(found);
    if (hasErrors(found)) return;
    setSubmitError(null);
    save.mutate();
  }

  if (!canWrite) {
    return (
      <p className="text-xs text-hcl-muted">
        Read-only: recording a decision requires the vex:write permission.
      </p>
    );
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-3">
      {/* Read-only context: what this decision is about, never re-pickable. */}
      <div className="rounded-lg bg-hcl-light/60 p-3 text-xs dark:bg-gray-900/40">
        <div className="flex flex-wrap gap-x-6 gap-y-1">
          <span>
            <span className="text-hcl-muted">Component: </span>
            <span className="font-medium">{componentLabel ?? `#${componentId}`}</span>
          </span>
          <span>
            <span className="text-hcl-muted">Vulnerability: </span>
            <span className="font-mono font-medium">{vulnerabilityId}</span>
          </span>
          {!investigation ? (
            <span className="text-hcl-muted">
              No investigation context yet — saving creates one.
            </span>
          ) : null}
        </div>
      </div>

      {submitError ? <Alert variant="error">{submitError}</Alert> : null}

      <Select
        label="Status"
        required
        value={draft.status}
        onChange={(event) => set('status', event.target.value as VexEffectiveStatus)}
        hint={guidance.hint}
      >
        {STATUS_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </Select>

      <Textarea
        label="Reason for this decision"
        required
        value={draft.reason}
        onChange={(event) => set('reason', event.target.value)}
        error={errors.reason}
        hint="Recorded in the audit trail."
      />

      <div className="grid gap-3 md:grid-cols-2">
        <Input
          label={isEmphasised('justification') ? 'Justification *' : 'Justification'}
          value={draft.justification}
          onChange={(event) => set('justification', event.target.value)}
          error={errors.justification}
        />
        <Input
          label={isEmphasised('fixedVersion') ? 'Fixed version *' : 'Fixed version'}
          value={draft.fixedVersion}
          onChange={(event) => set('fixedVersion', event.target.value)}
          error={errors.fixedVersion}
        />
        <Input
          label={isEmphasised('evidenceUrl') ? 'Evidence URL *' : 'Evidence URL'}
          type="url"
          value={draft.evidenceUrl}
          onChange={(event) => set('evidenceUrl', event.target.value)}
          error={errors.evidenceUrl}
        />
      </div>

      <Textarea
        label={isEmphasised('impactStatement') ? 'Impact statement *' : 'Impact statement'}
        value={draft.impactStatement}
        onChange={(event) => set('impactStatement', event.target.value)}
        error={errors.impactStatement}
      />

      {/* Kept available for every status, not just the emphasised ones: an
          analyst must still be able to record a mitigation on a NOT_AFFECTED. */}
      {mode === 'full' || isEmphasised('actionStatement') || draft.actionStatement ? (
        <Textarea
          label="Action statement"
          value={draft.actionStatement}
          onChange={(event) => set('actionStatement', event.target.value)}
        />
      ) : null}
      {mode === 'full' || isEmphasised('mitigation') || draft.mitigation ? (
        <Textarea
          label="Mitigation"
          value={draft.mitigation}
          onChange={(event) => set('mitigation', event.target.value)}
        />
      ) : null}

      <div className="flex justify-end gap-2 pt-1">
        {onCancel ? (
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        ) : null}
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving...' : 'Save decision'}
        </Button>
      </div>
    </form>
  );
}
