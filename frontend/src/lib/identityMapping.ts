/**
 * Canonical identity-mapping model and helper utilities.
 */

export type IdentityMappingMode =
  | 'CONNECTED'
  | 'LOCAL_ONLY'
  | 'UNVERIFIED'
  | 'UNAVAILABLE'
  | 'LEGACY';

export interface IdentityMappingInfo {
  mode: IdentityMappingMode;
  provider: string | null;
  displayStatus: string;
  externalTenantId: string | null;
  verified: boolean;
  isLegacy: boolean;
}

export function getDisplayStatusForMode(mode: IdentityMappingMode): string {
  switch (mode) {
    case 'CONNECTED':
      return 'HCL.CS connected';
    case 'LOCAL_ONLY':
      return 'Local authorization';
    case 'UNVERIFIED':
      return 'Mapping not verified';
    case 'UNAVAILABLE':
      return 'Identity mapping unavailable';
    case 'LEGACY':
      return 'Legacy record';
    default:
      return 'Local authorization';
  }
}

export function resolveIdentityMapping(
  mappingFromApi?: IdentityMappingInfo | Record<string, unknown> | null,
  rawExternalTenantId?: string | null,
  isApiError = false,
): IdentityMappingInfo {
  if (isApiError) {
    return {
      mode: 'UNAVAILABLE',
      provider: null,
      displayStatus: 'Identity mapping unavailable',
      externalTenantId: null,
      verified: false,
      isLegacy: false,
    };
  }

  if (mappingFromApi && typeof mappingFromApi === 'object') {
    const obj = mappingFromApi as Record<string, unknown>;
    const rawMode = (obj.mode ?? obj.mode) as string | undefined;
    const mode = (rawMode?.toUpperCase() as IdentityMappingMode) ?? 'LOCAL_ONLY';
    const provider = (obj.provider as string | null) ?? (obj.external_tenant_id || obj.externalTenantId ? 'HCL.CS' : null);
    const displayStatus =
      (obj.display_status as string) ??
      (obj.displayStatus as string) ??
      getDisplayStatusForMode(mode);
    const externalTenantId =
      ((obj.external_tenant_id ?? obj.externalTenantId ?? rawExternalTenantId) as string | null) ?? null;
    const verified = Boolean(obj.verified);
    const isLegacy = Boolean(obj.is_legacy ?? obj.isLegacy);

    return {
      mode,
      provider,
      displayStatus,
      externalTenantId: externalTenantId && externalTenantId.trim() !== '' ? externalTenantId : null,
      verified,
      isLegacy,
    };
  }

  const extId = (rawExternalTenantId || '').trim() || null;
  if (extId) {
    return {
      mode: 'CONNECTED',
      provider: 'HCL.CS',
      displayStatus: 'HCL.CS connected',
      externalTenantId: extId,
      verified: true,
      isLegacy: false,
    };
  }

  return {
    mode: 'LOCAL_ONLY',
    provider: null,
    displayStatus: 'Local authorization',
    externalTenantId: null,
    verified: false,
    isLegacy: false,
  };
}
