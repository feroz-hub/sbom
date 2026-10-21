import type { DashboardFilterScope } from '@/lib/api';
import { publicId } from '@/lib/publicId';

/** Discard orphaned child IDs from edited URLs before requesting data. */
export function parseDashboardScope(params: Pick<URLSearchParams, 'get'>): DashboardFilterScope {
  const projectId = publicId(params.get('project'));
  const applicationId = projectId ? publicId(params.get('application')) : null;
  return {
    projectId,
    applicationId,
    sbomId: applicationId ? publicId(params.get('sbom')) : null,
  };
}

/** Carry the dashboard hierarchy into list pages' existing URL filter names. */
export function dashboardDrilldownUrl(path: string, scope?: DashboardFilterScope): string {
  if (!scope?.projectId) return path;
  const [pathname, query = ''] = path.split('?');
  const params = new URLSearchParams(query);
  params.set('project', String(scope.projectId));
  if (scope.applicationId) params.set('product', String(scope.applicationId));
  if (scope.sbomId) params.set('sbom', String(scope.sbomId));
  return `${pathname}?${params.toString()}`;
}
