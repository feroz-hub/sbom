import { describe, expect, it } from 'vitest';
import { canOpenRepairWorkspace, getRepairWorkspaceUrl, REPAIR_WORKSPACE_ACCESS_STATUSES } from './repairWorkspace';

describe('repair workspace helper', () => {
  it('allows every supported workspace status', () => {
    for (const status of REPAIR_WORKSPACE_ACCESS_STATUSES) {
      expect(canOpenRepairWorkspace({ workspace_id: 'abc', validation_status: status })).toBe(true);
    }
  });

  it('returns false without a workspace id or URL', () => {
    expect(canOpenRepairWorkspace({ validation_status: 'failed' })).toBe(false);
  });

  it('builds the canonical repair route from workspace id', () => {
    expect(getRepairWorkspaceUrl({ validation_session_id: 'session-1' })).toBe('/repair/session-1');
  });
});
