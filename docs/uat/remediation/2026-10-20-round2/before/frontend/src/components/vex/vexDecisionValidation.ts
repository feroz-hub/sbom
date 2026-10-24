/**
 * One validator for VEX decisions, shared by every entry point.
 *
 * There used to be two: `validateVexOverride` on the SBOM page and `validate`
 * inside the investigation panel. They expressed the same three rules in
 * different words against different status vocabularies, which is exactly how
 * two screens start disagreeing about what a valid decision is.
 *
 * These rules mirror the backend (`_validate_vex_result` in
 * `app/services/lifecycle/vex_provider.py`, spec VEX-VAL-001/002). The backend
 * remains the gate — this exists so the analyst sees the problem before a
 * round trip, not instead of enforcement.
 */

import type { VexEffectiveStatus } from '@/types';

export interface VexDecisionDraft {
  status: VexEffectiveStatus;
  reason: string;
  justification: string;
  impactStatement: string;
  actionStatement: string;
  mitigation: string;
  fixedVersion: string;
  evidenceUrl: string;
}

/** Field-keyed errors, so each one renders against its own input. */
export type VexDecisionErrors = Partial<Record<keyof VexDecisionDraft, string>>;

export const EMPTY_DRAFT: VexDecisionDraft = {
  status: 'UNDER_INVESTIGATION',
  reason: '',
  justification: '',
  impactStatement: '',
  actionStatement: '',
  mitigation: '',
  fixedVersion: '',
  evidenceUrl: '',
};

/**
 * Which fields matter for a given status (spec sections 12-13).
 *
 * `required` drives validation. `emphasised` only drives presentation: every
 * field stays editable for every status, because an analyst must still be able
 * to record a mitigation on a NOT_AFFECTED. Hiding them would lose data the
 * backend happily stores.
 */
export const FIELD_GUIDANCE: Record<
  VexEffectiveStatus,
  { emphasised: Array<keyof VexDecisionDraft>; hint: string }
> = {
  NOT_AFFECTED: {
    emphasised: ['justification', 'impactStatement', 'evidenceUrl'],
    hint: 'Requires a justification or an impact statement explaining why this product is not affected.',
  },
  FIXED: {
    emphasised: ['fixedVersion', 'evidenceUrl'],
    hint: 'Requires the fixed version or evidence of the remediation.',
  },
  AFFECTED: {
    emphasised: ['impactStatement', 'actionStatement', 'mitigation'],
    hint: 'Record the impact and what consumers should do.',
  },
  UNDER_INVESTIGATION: {
    emphasised: ['impactStatement'],
    hint: 'No evidence is required yet; record what is known so far.',
  },
};

export function validateVexDecision(draft: VexDecisionDraft): VexDecisionErrors {
  const errors: VexDecisionErrors = {};

  // Required for every status: the audit trail is worthless without it.
  if (!draft.reason.trim()) {
    errors.reason = 'A reason is required.';
  }

  if (
    draft.status === 'NOT_AFFECTED' &&
    !draft.justification.trim() &&
    !draft.impactStatement.trim()
  ) {
    const message = 'NOT_AFFECTED requires a justification or an impact statement.';
    errors.justification = message;
    errors.impactStatement = message;
  }

  if (draft.status === 'FIXED' && !draft.fixedVersion.trim() && !draft.evidenceUrl.trim()) {
    const message = 'FIXED requires a fixed version or evidence.';
    errors.fixedVersion = message;
    errors.evidenceUrl = message;
  }

  return errors;
}

export function hasErrors(errors: VexDecisionErrors): boolean {
  return Object.keys(errors).length > 0;
}

/** First message, for a summary banner above the form. */
export function firstError(errors: VexDecisionErrors): string | null {
  const [first] = Object.values(errors);
  return first ?? null;
}
