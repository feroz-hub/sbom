import type { SbomValidationStatus, ValidationErrorEntry } from '@/types';

/** 1-based ordinal for each pipeline stage — mirrors STAGE_NUMBERS in app/validation/stages/__init__.py. */
export const STAGE_NUMBERS: Record<string, number> = {
  ingress: 1,
  detect: 2,
  schema: 3,
  semantic: 4,
  integrity: 5,
  security: 6,
  ntia: 7,
  signature: 8,
};

/** Human-readable label per stage — matches the backend STAGE_LABELS table. */
export const STAGE_LABELS: Record<string, string> = {
  ingress: 'Ingress Guard',
  detect: 'Format Detection',
  schema: 'Structural Schema',
  semantic: 'Semantic Validation',
  integrity: 'Cross-Reference Integrity',
  security: 'Security Checks',
  ntia: 'NTIA Minimum Elements',
  signature: 'Signature Verification',
};

export function stageLabel(stage: string | null | undefined): string {
  if (!stage) return 'Unknown stage';
  return STAGE_LABELS[stage] ?? stage;
}

export function stageNumber(stage: string | null | undefined): number {
  if (!stage) return 0;
  return STAGE_NUMBERS[stage] ?? 0;
}

/**
 * Group entries by stage, preserving the order entries appeared in the
 * report. Within each stage entries are ordered by severity (errors first,
 * then warnings, then info) so the user sees blocking issues first.
 */
export function groupEntriesByStage(
  entries: ValidationErrorEntry[],
): Array<{ stage: string; entries: ValidationErrorEntry[] }> {
  const order: string[] = [];
  const buckets = new Map<string, ValidationErrorEntry[]>();
  for (const e of entries) {
    if (!buckets.has(e.stage)) {
      order.push(e.stage);
      buckets.set(e.stage, []);
    }
    buckets.get(e.stage)!.push(e);
  }
  const sevRank: Record<string, number> = { error: 0, warning: 1, info: 2 };
  return order.map((stage) => ({
    stage,
    entries: [...(buckets.get(stage) ?? [])].sort(
      (a, b) => (sevRank[a.severity] ?? 99) - (sevRank[b.severity] ?? 99),
    ),
  }));
}

export interface StatusMeta {
  label: string;
  description: string;
  /** Tailwind class fragment for badge background + text + border. */
  classes: string;
}

const _OK = 'border-green-200 bg-green-50 text-green-700 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200';
const _WARN = 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-200';
const _FAIL = 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/50 dark:text-red-200';
const _QUARANTINE = 'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950/50 dark:text-purple-200';
const _PENDING = 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-300';

export function validationStatusMeta(
  status: SbomValidationStatus | undefined,
  warningCount = 0,
): StatusMeta {
  switch (status) {
    case 'failed':
      return { label: 'Validation failed', description: 'One or more stages rejected this SBOM.', classes: _FAIL };
    case 'quarantined':
      return {
        label: 'Quarantined',
        description: 'Security stage flagged this upload — admin review required.',
        classes: _QUARANTINE,
      };
    case 'pending':
      return { label: 'Validation pending', description: 'Validation has not run yet.', classes: _PENDING };
    case 'validated':
    default:
      if (warningCount > 0) {
        return {
          label: 'Validated · warnings',
          description: `Passed validation with ${warningCount} non-blocking warning${warningCount === 1 ? '' : 's'}.`,
          classes: _WARN,
        };
      }
      return { label: 'Validated', description: 'Passed all 8 validation stages.', classes: _OK };
  }
}

/** Tailwind classes for a per-entry severity chip. */
export function severityChipClasses(severity: string): string {
  switch (severity) {
    case 'error':
      return 'bg-red-100 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800';
    case 'warning':
      return 'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800';
    case 'info':
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800/60 dark:text-slate-300 dark:border-slate-700';
  }
}
