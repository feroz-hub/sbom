import type { AiConnectionTestResult } from '@/types/ai';

export type VerificationState = 'VERIFIED' | 'UNVERIFIED' | 'TEMPORARILY_UNAVAILABLE' | 'INVALID_CREDENTIALS' | 'INVALID_CONFIGURATION';

/** Only typed outcomes determine status. Provider text is never trusted/displayed. */
export function verificationState(result?: AiConnectionTestResult | null, error?: unknown): VerificationState {
  if (error) {
    const status = typeof error === 'object' && 'status' in error ? Number(error.status) : 0;
    // These are errors from SBOM itself, not evidence of invalid upstream keys.
    if ([400, 422].includes(status)) return 'INVALID_CONFIGURATION';
    if (status === 429 || status >= 500) return 'TEMPORARILY_UNAVAILABLE';
    return 'UNVERIFIED';
  }
  if (result?.success) return 'VERIFIED';
  if (result?.error_kind === 'auth') return 'INVALID_CREDENTIALS';
  if (['rate_limit', 'provider_unavailable'].includes(result?.error_kind ?? '')) return 'TEMPORARILY_UNAVAILABLE';
  return 'UNVERIFIED';
}

export function verificationMessage(result?: AiConnectionTestResult | null, error?: unknown) {
  const state = verificationState(result, error);
  switch (state) {
    case 'VERIFIED': return { state, title: 'Connection successful', text: 'The provider configuration was verified successfully.' };
    case 'INVALID_CREDENTIALS': return { state, title: 'Authentication failed', text: 'The provider rejected these credentials. Check the API key and permissions before continuing.' };
    case 'INVALID_CONFIGURATION': return { state, title: 'Complete the required configuration', text: 'Review the required fields before saving or testing again.' };
    case 'TEMPORARILY_UNAVAILABLE': return { state, title: 'Provider temporarily unavailable', text: result?.error_kind === 'rate_limit' ? 'The provider is currently rate-limiting requests. Your configuration can be saved and tested again later.' : result?.provider === 'gemini' && result.http_status === 503 ? 'The selected Gemini model may be experiencing high demand. Your API key has not been identified as invalid. You can save this configuration and verify it later.' : 'The provider or selected model could not complete verification. This may be temporary. You can save the configuration and test it again later.' };
    default: return { state, title: 'Connection could not be verified', text: result?.error_kind === 'model_not_found' || result?.error_kind === 'configuration' ? 'Review the selected model and provider configuration. The API key has not been identified as invalid. You can save and test again later.' : 'The connection test could not be completed. SBOM Analyzer could not verify the provider. Your configuration can still be saved securely and tested again later.' };
  }
}
