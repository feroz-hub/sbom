'use client';

/**
 * `useMutation`-based wrappers for the two SBOM write paths that
 * previously used raw `await` inside component event handlers.
 *
 * Centralising these so the Phase 3 forbidding test catches future
 * write surfaces, and so the "which caches to invalidate" mapping
 * lives next to the mutation instead of inside each caller.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { HttpError, revalidateSbom, uploadSbom } from '@/lib/api';
import {
  invalidateSbomLists,
  invalidateUploadSurfaces,
} from '@/lib/queryInvalidation';
import type {
  CreateSBOMPayload,
  SBOMSource,
  SbomValidationFailureDetail,
} from '@/types';

function isValidationFailureDetail(
  detail: unknown,
): detail is SbomValidationFailureDetail {
  return (
    typeof detail === 'object' &&
    detail !== null &&
    (detail as { code?: unknown }).code === 'sbom_validation_failed'
  );
}

/**
 * Upload an SBOM. On success the hook refreshes only the SBOM list,
 * affected project detail, and dashboard summary surfaces.
 *
 * Callers can still attach their own `onSuccess` at mutate-time for
 * optimistic UX (e.g. inserting the new row immediately) or to fire
 * background analysis.
 */
export function useUploadSbom() {
  const qc = useQueryClient();
  return useMutation<SBOMSource, Error, CreateSBOMPayload>({
    mutationFn: (payload) => uploadSbom(payload),
    onSuccess: (sbom) => {
      invalidateUploadSurfaces(qc, sbom.project_id ?? sbom.projectid);
    },
  });
}

/**
 * Re-run validation against an already-uploaded SBOM body.
 *
 * A 4xx with `code: 'sbom_validation_failed'` is treated as a
 * successful run that produced errors — the operation succeeded, the
 * SBOM just didn't pass. We still invalidate so the report card
 * re-renders in its failed form.
 */
export function useRevalidateSbom(sbomId: number) {
  const qc = useQueryClient();
  return useMutation<void, Error, void>({
    mutationFn: async () => {
      try {
        await revalidateSbom(sbomId);
      } catch (err) {
        if (err instanceof HttpError && isValidationFailureDetail(err.detail)) {
          // Expected outcome — the run succeeded, the SBOM didn't pass.
          // Swallow so onSuccess fires and consumers refresh.
          return;
        }
        throw err;
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sbom-validation-report', sbomId] });
      qc.invalidateQueries({ queryKey: ['sbom', sbomId] });
      qc.invalidateQueries({ queryKey: ['sbom-info', sbomId] });
      // Validation status surfaces in the main list's Upload column.
      invalidateSbomLists(qc);
    },
  });
}
