import { describe, expect, it } from 'vitest';
import { cachedRecordLabel } from './recordDisplay';

const id = 'f5e7f4c4-8a16-4c70-93d8-092173885437';
describe('old pinned label presentation', () => {
  it('retains the name without inventing the old pin integer', () => {
    expect(cachedRecordLabel(`Gateway · #${id}`, id, 'Run')).toBe('Gateway');
    expect(cachedRecordLabel(`Gateway — Run #${id}`, id, 'Run')).toBe('Gateway');
  });
  it('uses unavailable labels for identity-only pins', () => {
    expect(cachedRecordLabel(`Run #${id}`, id, 'Run')).toBe('Run —');
    expect(cachedRecordLabel(`SBOM #${id}`, id, 'SBOM')).toBe('SBOM —');
  });
  it('preserves unrelated technical references and actual integer labels', () => {
    expect(cachedRecordLabel(`Source-native #${id}`, id, 'SBOM')).toBe(`Source-native #${id}`);
    expect(cachedRecordLabel('Gateway · Run #891', id, 'Run')).toBe('Gateway · Run #891');
    expect(cachedRecordLabel('Run #123', 123, 'Run')).toBe('Run #123');
  });
});
