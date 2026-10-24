/**
 * CveDetailDialog — public entry.
 *
 * Feature version: **2.1** (2026-04-30)
 *   2.1 — identifier taxonomy: 5 ID kinds (CVE/GHSA/PYSEC/RUSTSEC/GO),
 *         frontend classifier mirror short-circuits unknown IDs without
 *         a network round-trip; per-state banner taxonomy
 *         (loading/ok/partial/not_found/unreachable/unrecognized/fatal);
 *         clickable alias-chip swap; backend ``CveResultStatus`` discriminator
 *         and ``CVE_VAL_E001_UNRECOGNIZED_ID`` 400 envelope.
 *   2.0 — first ship: 3-section modal, scan-aware variant, lazy body.
 */
export { CveDetailDialog } from './CveDetailDialog';
export type { CveDetailDialogProps } from './CveDetailDialog';
export { useCveDetail, useCveHoverPrefetch, cveQueryKey } from './hooks';
export type { CveRowSeed } from './types';
export { selectDialogState } from './states';
export type { DialogState } from './states';
