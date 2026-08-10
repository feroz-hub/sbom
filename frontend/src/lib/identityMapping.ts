/**
 * Canonical external tenant mapping model and helper utilities.
 *
 * Architecture principles:
 * 1. Authentication is ALWAYS handled via HCL.CS for interactive users.
 * 2. Tenant access (memberships & roles) is database-authoritative inside SBOM.
 * 3. external_iam_tenant_id represents optional external tenant mapping.
 * 4. A null external mapping MUST NOT be labeled "Local authentication" or "Local authorization".
 */

export type ExternalTenantMappingState =
  | 'CONNECTED'
  | 'NOT_CONFIGURED'
  | 'UNVERIFIED'
  | 'UNAVAILABLE'
  | 'LEGACY';

export type IdentityMappingMode = ExternalTenantMappingState;

export interface IdentityMappingInfo {
  state: ExternalTenantMappingState;
  mode: ExternalTenantMappingState;
  provider: string | null;
  displayStatus: string;
  externalTenantId: string | null;
  verified: boolean;
  isLegacy: boolean;
}

export function getExternalMappingLabel(state: ExternalTenantMappingState): string {
  switch (state) {
    case 'CONNECTED':
      return 'Connected to HCL.CS tenant';
    case 'NOT_CONFIGURED':
      return 'Not configured';
    case 'UNVERIFIED':
      return 'Mapping not verified';
    case 'UNAVAILABLE':
      return 'Mapping status unavailable';
    case 'LEGACY':
      return 'Legacy record';
    default:
      return 'Not configured';
  }
}

export function getDisplayStatusForMode(mode: IdentityMappingMode): string {
  return getExternalMappingLabel(mode);
}

export function resolveExternalTenantMapping(
  mappingFromApi?: IdentityMappingInfo | Record<string, unknown> | null,
  rawExternalTenantId?: string | null,
  isApiError = false,
): IdentityMappingInfo {
  if (isApiError) {
    return {
      state: 'UNAVAILABLE',
      mode: 'UNAVAILABLE',
      provider: null,
      displayStatus: 'Mapping status unavailable',
      externalTenantId: null,
      verified: false,
      isLegacy: false,
    };
  }

  if (mappingFromApi && typeof mappingFromApi === 'object') {
    const obj = mappingFromApi as Record<string, unknown>;
    const isLegacy = Boolean(obj.is_legacy ?? obj.isLegacy);
    const rawExtId = (obj.external_tenant_id ?? obj.externalTenantId ?? rawExternalTenantId) as string | null;
    const externalTenantId = rawExtId && String(rawExtId).trim() !== '' ? String(rawExtId).trim() : null;

    if (isLegacy) {
      return {
        state: 'LEGACY',
        mode: 'LEGACY',
        provider: 'HCL.CS',
        displayStatus: 'Legacy record',
        externalTenantId,
        verified: Boolean(obj.verified),
        isLegacy: true,
      };
    }

    const rawState = (obj.state ?? obj.mode) as string | undefined;
    if (rawState) {
      const stateUpper = rawState.toUpperCase();
      let state: ExternalTenantMappingState = 'NOT_CONFIGURED';
      if (stateUpper === 'CONNECTED') state = 'CONNECTED';
      else if (stateUpper === 'UNVERIFIED') state = 'UNVERIFIED';
      else if (stateUpper === 'UNAVAILABLE') state = 'UNAVAILABLE';
      else if (stateUpper === 'LEGACY') state = 'LEGACY';
      else if (stateUpper === 'NOT_CONFIGURED' || stateUpper === 'LOCAL_ONLY') state = 'NOT_CONFIGURED';

      const customDisplay = (obj.display_status ?? obj.displayStatus) as string | undefined;
      const displayStatus =
        customDisplay &&
        customDisplay !== 'Local authorization' &&
        customDisplay !== 'HCL.CS connected'
          ? customDisplay
          : getExternalMappingLabel(state);

      return {
        state,
        mode: state,
        provider: externalTenantId ? 'HCL.CS' : null,
        displayStatus,
        externalTenantId,
        verified: Boolean(obj.verified),
        isLegacy: false,
      };
    }
  }

  const extId = (rawExternalTenantId || '').trim() || null;
  if (extId) {
    return {
      state: 'CONNECTED',
      mode: 'CONNECTED',
      provider: 'HCL.CS',
      displayStatus: 'Connected to HCL.CS tenant',
      externalTenantId: extId,
      verified: true,
      isLegacy: false,
    };
  }

  return {
    state: 'NOT_CONFIGURED',
    mode: 'NOT_CONFIGURED',
    provider: null,
    displayStatus: 'Not configured',
    externalTenantId: null,
    verified: false,
    isLegacy: false,
  };
}

export function resolveIdentityMapping(
  mappingFromApi?: IdentityMappingInfo | Record<string, unknown> | null,
  rawExternalTenantId?: string | null,
  isApiError = false,
): IdentityMappingInfo {
  return resolveExternalTenantMapping(mappingFromApi, rawExternalTenantId, isApiError);
}
