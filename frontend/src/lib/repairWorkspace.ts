export const REPAIR_WORKSPACE_ACCESS_STATUSES = new Set([
  'failed',
  'unsupported',
  'unsupported_format',
  'valid',
  'validated',
  'valid_with_warnings',
  'warning',
  'repair_draft',
  'repaired',
  'repaired_valid',
  'imported',
]);

export interface RepairWorkspaceLinkable {
  workspace_id?: number | string | null;
  validation_session_id?: number | string | null;
  session_id?: number | string | null;
  repair_workspace_url?: string | null;
  workspace_available?: boolean | null;
  workspace_source?: string | null;
  validation_status?: string | null;
  status?: string | null;
}

export function canOpenRepairWorkspace(item: RepairWorkspaceLinkable): boolean {
  const workspaceId = item.workspace_id ?? item.validation_session_id ?? item.session_id;
  const status = item.validation_status ?? item.status;
  if (!workspaceId && !item.repair_workspace_url) {
    return Boolean(item.workspace_available && item.workspace_source === 'backfillable');
  }
  if (!status) return Boolean(workspaceId || item.repair_workspace_url);
  return REPAIR_WORKSPACE_ACCESS_STATUSES.has(String(status).toLowerCase());
}

export function getRepairWorkspaceUrl(item: RepairWorkspaceLinkable): string | null {
  if (item.repair_workspace_url) return item.repair_workspace_url;
  const id = item.workspace_id ?? item.validation_session_id ?? item.session_id;
  return id ? `/repair/${id}` : null;
}

export function repairWorkspaceLabel(status?: string | null): string {
  const normalized = String(status || '').toLowerCase();
  if (normalized === 'valid_with_warnings' || normalized === 'warning') return 'Review / Repair Workspace';
  if (normalized === 'valid' || normalized === 'validated' || normalized === 'imported' || normalized === 'repaired_valid') return 'Open Repair Workspace';
  if (normalized === 'unsupported' || normalized === 'unsupported_format') return 'Open Workspace';
  return 'Open Repair Workspace';
}
