import { describe, expect, it } from 'vitest';
import { hasVerificationProof, providerStatus, selectProviders, summarizeProviders } from './lifecycle-provider-presentation';
import { makeProvider, successfulProbe } from '@/test/lifecycle-provider-fixtures';

describe('lifecycle presentation semantics', () => {
  it('does not trust enabled state, a healthy row, a timestamp, or HTTP success alone', () => {
    expect(summarizeProviders([makeProvider({ health_status: 'healthy', last_success_at: '2026-10-16' })]).verified).toBe(0);
    expect(hasVerificationProof(makeProvider({ last_probe: { ...successfulProbe, response_valid: false } }))).toBe(false);
    expect(hasVerificationProof(makeProvider({ last_probe: { ...successfulProbe, connection_verified: false } }))).toBe(false);
  });
  it('keeps static reference checks separate from operational verified counts', () => {
    const row = makeProvider({ last_probe: { ...successfulProbe, probe_type: 'local_verification', connection_verified: false, real_provider_call: false } }, { network: false, data_source_type: 'Static Reference' });
    expect(providerStatus(row).label).toBe('Reference checked'); expect(summarizeProviders([row]).verified).toBe(0);
  });
  it('does not count degraded or unsupported sources as verified', () => {
    expect(summarizeProviders([makeProvider({ last_probe: successfulProbe, health_status: 'degraded' }), makeProvider({ last_probe: successfulProbe }, { implemented: false })])).toMatchObject({ verified: 0, attention: 1, unsupported: 1 });
  });
  it('sorts last successful stored verifications before unverified rows', () => {
    const rows = [makeProvider({ provider_key: 'unverified' }), makeProvider({ provider_key: 'verified', last_probe: successfulProbe })];
    expect(selectProviders(rows, '', 'All', 'verified')[0].provider_key).toBe('verified');
  });
  it('filters unsupported sources from capabilities, not a guessed key', () => { expect(selectProviders([makeProvider({}, { implemented: false })], '', 'Unsupported', 'name')).toHaveLength(1); });
});
