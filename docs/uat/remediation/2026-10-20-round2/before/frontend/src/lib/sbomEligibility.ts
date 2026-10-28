import type { SBOMSource } from '@/types';

export type ProcessingEligibility = { eligible: boolean; reason_code: string | null; reason: string | null };

/** Prefer the server verdict; fallback supports older API responses. */
export function sbomEligibility(sbom: SBOMSource): ProcessingEligibility {
  if (sbom.lifecycle_status === 'INACTIVE') return { eligible: false, reason_code: 'SBOM_INACTIVE', reason: 'Analysis unavailable because this SBOM is inactive.' };
  if (sbom.processing_eligibility?.eligible != null) return sbom.processing_eligibility;
  if (sbom.status === 'quarantined') return { eligible: false, reason_code: 'SBOM_UNSAFE', reason: 'Processing unavailable because this SBOM is unsafe or quarantined.' };
  if (sbom.status === 'pending') return { eligible: false, reason_code: 'SBOM_VALIDATION_PENDING', reason: 'Processing unavailable while SBOM validation is pending.' };
  if ((sbom.status && sbom.status !== 'validated') || (sbom.error_count ?? 0) > 0 || sbom.validation_errors?.some(entry => String(entry.severity).toLowerCase() === 'error')) {
    return { eligible: false, reason_code: 'SBOM_VALIDATION_BLOCKED', reason: 'Processing unavailable because this SBOM has unresolved blocking validation failures.' };
  }
  return { eligible: true, reason_code: null, reason: null };
}
