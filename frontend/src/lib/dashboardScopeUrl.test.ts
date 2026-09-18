import { describe, expect, it } from 'vitest';
import { dashboardDrilldownUrl, parseDashboardScope } from './dashboardScopeUrl';

describe('dashboard URL scope', () => {
  it('preserves valid hierarchy on refresh and drilldown', () => {
    const scope = parseDashboardScope(new URLSearchParams('project=1&application=2&sbom=3'));
    expect(scope).toEqual({ projectId: 1, applicationId: 2, sbomId: 3 });
    expect(dashboardDrilldownUrl('/analysis?tab=vulnerabilities', scope))
      .toBe('/analysis?tab=vulnerabilities&project=1&product=2&sbom=3');
  });

  it('ignores orphaned or malformed child IDs', () => {
    expect(parseDashboardScope(new URLSearchParams('application=2&sbom=3')))
      .toEqual({ projectId: null, applicationId: null, sbomId: null });
    expect(parseDashboardScope(new URLSearchParams('project=1&sbom=3')))
      .toEqual({ projectId: 1, applicationId: null, sbomId: null });
    expect(parseDashboardScope(new URLSearchParams('project=NaN&application=2')))
      .toEqual({ projectId: null, applicationId: null, sbomId: null });
  });
});
