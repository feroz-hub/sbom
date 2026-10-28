/** Actual backend catalogue codes; no frontend role-to-permission mapping. */
const actions: Record<string, string> = {
  'project:create': 'create projects', 'project:update': 'edit projects', 'project:delete': 'delete projects',
  'product:assign_sbom': 'assign SBOMs to applications', 'product:manage_schedule': 'manage application schedules',
  'product:create': 'create applications', 'product:update': 'edit applications', 'product:delete': 'delete applications',
  'sbom:upload': 'upload SBOM files', 'sbom:update': 'update SBOMs', 'sbom:delete': 'delete SBOMs', 'sbom:export': 'export SBOMs',
  'sbom:repair:update': 'edit and save repair drafts', 'sbom:repair:revalidate': 'revalidate or import repair sessions',
  'sbom:repair:download': 'download repair files and reports', 'analysis:run': 'run vulnerability analysis',
  'schedule:write': 'manage analysis schedules', 'vex:write': 'update VEX investigations', 'component:update': 'update components',
  'remediation:write': 'update remediation actions', 'remediation:close': 'close remediation actions',
  'tenant:settings:update': 'manage tenant settings', 'tenant:user:invite': 'invite users', 'tenant:user:update': 'manage users',
  'tenant:ai:update': 'configure tenant AI providers', 'tenant:ai:test': 'verify tenant AI providers',
  'component_advisor:recommendation:create': 'create component recommendations',
  'lifecycle:override': 'override lifecycle information', 'lifecycle:vendor-record:write': 'manage lifecycle vendor records', 'lifecycle:vendor-record:delete': 'disable lifecycle vendor records',
  'platform:ai:update': 'configure platform AI providers', 'platform:ai:test': 'verify platform AI providers',
};
export function permissionReason(permission?: string): string {
  return `You don't have permission to ${permission && actions[permission] || 'perform this action'}. Contact your administrator to request access.`;
}
export const RESOURCE_NOT_ASSIGNED = 'This investigation is not assigned to you.';

/** Read access for direct URLs, including destinations outside the sidebar. */
export function routePermissions(path: string): string[] | null {
  if (path.startsWith('/docs/')) return null;
  if (path.startsWith('/platform/configuration/ai')) return ['platform:ai:read'];
  if (path.startsWith('/platform/configuration/lifecycle')) return ['platform:lifecycle-provider:read'];
  if (path.startsWith('/platform/configuration/advisor-policies')) return ['platform:advisor-policy:read'];
  if (path.startsWith('/settings/platform/tenants')) return ['platform:tenant:read'];
  if (path.startsWith('/settings/platform')) return ['platform:administrator:read'];
  if (path.startsWith('/settings/iam')) return ['platform:health:read'];
  if (path.startsWith('/settings/users') || path.startsWith('/settings/native-users')) return ['tenant:user:read'];
  if (path.startsWith('/settings/ai')) return ['tenant:ai:read'];
  if (path.startsWith('/settings/advisor-policies')) return ['tenant:advisor-policy:read'];
  if (path.startsWith('/settings/notifications')) return ['sbom:read'];
  if (path.startsWith('/settings/tenant')) return ['tenant:user:read'];
  if (path === '/settings') return null; // Includes authenticated self-service password/session controls.
  if (path.startsWith('/admin/lifecycle-providers')) return ['tenant:lifecycle-provider:read'];
  if (path.startsWith('/admin/lifecycle-vendor-records')) return ['lifecycle:vendor-record:read'];
  if (path.startsWith('/admin/ai-usage')) return ['dashboard:read'];
  if (path.startsWith('/platform')) return ['platform:tenant:read'];
  if (path.startsWith('/projects')) return ['project:read'];
  if (path.startsWith('/products')) return ['product:read'];
  if (path.startsWith('/repair') || path.startsWith('/sbom-validation-sessions')) return ['sbom:repair:read'];
  if (path.startsWith('/sboms')) return ['sbom:read'];
  if (path.startsWith('/analysis') || path.startsWith('/kev')) return ['analysis:read'];
  if (path.startsWith('/vex-investigation')) return ['vex:read'];
  if (path.startsWith('/component-advisor')) return ['component_advisor:read'];
  if (path.startsWith('/schedules')) return ['schedule:read'];
  return path === '/' ? ['dashboard:read'] : null;
}
