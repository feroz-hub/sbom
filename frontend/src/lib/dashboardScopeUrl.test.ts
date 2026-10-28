import { describe, expect, it } from 'vitest';
import { dashboardDrilldownUrl, parseDashboardScope } from './dashboardScopeUrl';

describe('dashboard URL scope', () => {
  const project = 'd4828e7c-e71c-40f7-bb6c-dde0f4d48d09';
  const application = '60de2b20-c45c-4a49-9b36-e0af7b5790fc';
  const sbom = '729992e8-b107-4d3d-96a9-5cac4bcf5f8d';
  const empty = { projectId: null, applicationId: null, sbomId: null };
  it('preserves valid hierarchy on refresh and drilldown', () => {
    const scope = parseDashboardScope(new URLSearchParams(`project=${project}&application=${application}&sbom=${sbom}`));
    expect(scope).toEqual({ projectId: project, applicationId: application, sbomId: sbom });
    expect(dashboardDrilldownUrl('/analysis?tab=vulnerabilities', scope))
      .toBe(`/analysis?tab=vulnerabilities&project=${project}&product=${application}&sbom=${sbom}`);
  });

  it('ignores orphaned or malformed child IDs', () => {
    expect(parseDashboardScope(new URLSearchParams(`application=${application}&sbom=${sbom}`))).toEqual(empty);
    expect(parseDashboardScope(new URLSearchParams(`project=${project}&sbom=${sbom}`)))
      .toEqual({ projectId: project, applicationId: null, sbomId: null });
    expect(parseDashboardScope(new URLSearchParams(`project=NaN&application=${application}`))).toEqual(empty);
    expect(parseDashboardScope(new URLSearchParams(`project=${project}&application=invalid&sbom=${sbom}`)))
      .toEqual({ projectId: project, applicationId: null, sbomId: null });
  });

  it('normalizes uppercase UUIDs through the existing public ID boundary', () => {
    expect(parseDashboardScope(new URLSearchParams(`project=${project.toUpperCase()}`)))
      .toEqual({ projectId: project, applicationId: null, sbomId: null });
  });

  it.each(['', '1', '0', '-1', '1e3', 'NaN', 'Infinity', 'undefined',
    '00000000-0000-0000-0000-000000000000',
    'd4828e7c-e71c-10f7-bb6c-dde0f4d48d09',
    'd4828e7c-e71c-40f7-0b6c-dde0f4d48d09',
    ` ${project}`, `${project}/extra`, '<script>alert(1)</script>',
  ])('rejects invalid public ID %j without retaining child scope', value => {
    expect(parseDashboardScope(new URLSearchParams({project:value,application,sbom}))).toEqual(empty);
  });

  it('keeps unfiltered drilldowns unchanged', () => {
    expect(parseDashboardScope(new URLSearchParams())).toEqual(empty);
    expect(dashboardDrilldownUrl('/projects?sort=name', empty)).toBe('/projects?sort=name');
  });
});
