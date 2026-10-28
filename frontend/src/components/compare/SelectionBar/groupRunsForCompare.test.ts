/**
 * Unit tests for ``groupRunsForCompare``.
 *
 * The helper is the load-bearing piece of the "smart picker" UX so we cover
 * the corners exhaustively here and keep the integration tests in
 * ``RunPicker.test.tsx`` focused on rendering / a11y.
 */

import { describe, expect, it } from 'vitest';
import {
  groupRunsForCompare,
  isSameLogicalSbom,
} from './groupRunsForCompare';
import type { RunSummary } from '@/types/compare';

const makeRun = (over: Partial<RunSummary> & { id: string }): RunSummary => ({
  id: over.id,
  sbom_id: over.sbom_id ?? null,
  sbom_name: over.sbom_name ?? null,
  project_id: over.project_id ?? null,
  project_name: over.project_name ?? null,
  run_status: over.run_status ?? 'FINDINGS',
  completed_on: over.completed_on ?? null,
  started_on: over.started_on ?? null,
  total_findings: over.total_findings ?? 0,
  total_components: over.total_components ?? 0,
});

describe('isSameLogicalSbom', () => {
  it('matches when sbom_name AND project_id are equal', () => {
    const a = makeRun({ id: "00000000-0000-4000-8000-000000000001", sbom_name: 'app', project_id: 10 });
    const b = makeRun({ id: "00000000-0000-4000-8000-000000000002", sbom_name: 'app', project_id: 10 });
    expect(isSameLogicalSbom(a, b)).toBe(true);
  });

  it('does not match across projects, even with the same name', () => {
    // Two projects can share an SBOM filename but they are different
    // logical SBOMs — explicitly forbidden by the spec.
    const a = makeRun({ id: "00000000-0000-4000-8000-000000000001", sbom_name: 'app', project_id: 10 });
    const b = makeRun({ id: "00000000-0000-4000-8000-000000000002", sbom_name: 'app', project_id: 99 });
    expect(isSameLogicalSbom(a, b)).toBe(false);
  });

  it('does not match when names differ', () => {
    const a = makeRun({ id: "00000000-0000-4000-8000-000000000001", sbom_name: 'app', project_id: 10 });
    const b = makeRun({ id: "00000000-0000-4000-8000-000000000002", sbom_name: 'other', project_id: 10 });
    expect(isSameLogicalSbom(a, b)).toBe(false);
  });

  it('returns false when either side has a null sbom_name', () => {
    const a = makeRun({ id: "00000000-0000-4000-8000-000000000001", sbom_name: null, project_id: 10 });
    const b = makeRun({ id: "00000000-0000-4000-8000-000000000002", sbom_name: null, project_id: 10 });
    expect(isSameLogicalSbom(a, b)).toBe(false);
  });
});

describe('groupRunsForCompare', () => {
  it('returns everything in `other` (date-desc) when no paired run is given', () => {
    const r1 = makeRun({ id: "00000000-0000-4000-8000-000000000001", completed_on: '2026-01-01T00:00:00Z' });
    const r2 = makeRun({ id: "00000000-0000-4000-8000-000000000002", completed_on: '2026-03-01T00:00:00Z' });
    const r3 = makeRun({ id: "00000000-0000-4000-8000-000000000003", completed_on: '2026-02-01T00:00:00Z' });

    const grouped = groupRunsForCompare([r1, r2, r3], null);

    expect(grouped.primary).toEqual([]);
    expect(grouped.other.map((r) => r.id)).toEqual(['00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001']);
  });

  it('splits primary (same SBOM) vs other and sorts each newest-first', () => {
    const paired = makeRun({
      id: "00000000-0000-4000-8000-000000000007",
      sbom_name: 'app-sbom',
      project_id: 1,
      completed_on: '2026-05-06T23:51:00Z',
    });
    const sameSbomOlder = makeRun({
      id: "00000000-0000-4000-8000-000000000006",
      sbom_name: 'app-sbom',
      project_id: 1,
      completed_on: '2026-05-01T03:17:00Z',
    });
    const sameSbomOldest = makeRun({
      id: "00000000-0000-4000-8000-000000000005",
      sbom_name: 'app-sbom',
      project_id: 1,
      completed_on: '2026-04-28T11:47:00Z',
    });
    const otherSbomNewer = makeRun({
      id: "00000000-0000-4000-8000-000000000004",
      sbom_name: 'cyclonedx-multi-ecosystem',
      project_id: 1,
      completed_on: '2026-05-05T11:49:00Z',
    });
    const otherSbomOlder = makeRun({
      id: "00000000-0000-4000-8000-000000000003",
      sbom_name: 'Test Sbom',
      project_id: 1,
      completed_on: '2026-05-01T03:18:00Z',
    });

    const grouped = groupRunsForCompare(
      [sameSbomOlder, otherSbomNewer, otherSbomOlder, sameSbomOldest, paired],
      paired,
    );

    expect(grouped.primary.map((r) => r.id)).toEqual(['00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000005']);
    expect(grouped.other.map((r) => r.id)).toEqual(['00000000-0000-4000-8000-000000000004', '00000000-0000-4000-8000-000000000003']);
  });

  it('always excludes the paired run itself (no degenerate self-compare)', () => {
    const paired = makeRun({
      id: "00000000-0000-4000-8000-000000000007",
      sbom_name: 'app-sbom',
      project_id: 1,
      completed_on: '2026-05-06T23:51:00Z',
    });
    const grouped = groupRunsForCompare([paired], paired);
    expect(grouped.primary).toEqual([]);
    expect(grouped.other).toEqual([]);
  });

  it('returns an empty primary section when only one run of the SBOM exists', () => {
    // Reproduces the screenshot scenario: app-sbom has only run #7, so
    // picking it in Run A should leave the primary section empty (the UI
    // renders the hint banner for that case).
    const paired = makeRun({
      id: "00000000-0000-4000-8000-000000000007",
      sbom_name: 'app-sbom',
      project_id: 1,
      completed_on: '2026-05-06T23:51:00Z',
    });
    const others = [
      makeRun({
        id: "00000000-0000-4000-8000-000000000006",
        sbom_name: 'USERINTERFACE-0.1.0.cdx',
        project_id: 1,
        completed_on: '2026-05-05T23:49:00Z',
      }),
      makeRun({
        id: "00000000-0000-4000-8000-000000000004",
        sbom_name: 'cyclonedx-multi-ecosystem',
        project_id: 1,
        completed_on: '2026-05-01T03:18:00Z',
      }),
    ];

    const grouped = groupRunsForCompare([paired, ...others], paired);

    expect(grouped.primary).toEqual([]);
    expect(grouped.other.map((r) => r.id)).toEqual(['00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000004']);
  });

  it('does not group across projects even when sbom_name matches', () => {
    const paired = makeRun({ id: "00000000-0000-4000-8000-000000000001", sbom_name: 'shared', project_id: 10 });
    const sameNameOtherProject = makeRun({
      id: "00000000-0000-4000-8000-000000000002",
      sbom_name: 'shared',
      project_id: 11,
    });

    const grouped = groupRunsForCompare([sameNameOtherProject], paired);

    expect(grouped.primary).toEqual([]);
    expect(grouped.other.map((r) => r.id)).toEqual(['00000000-0000-4000-8000-000000000002']);
  });
});
