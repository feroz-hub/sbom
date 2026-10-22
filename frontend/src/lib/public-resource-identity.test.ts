// @vitest-environment jsdom
import { beforeEach, expect, it } from 'vitest';
import { publicId } from './publicId';
import { addPendingAnalysis, clearStalePendingAnalyses, getStillPendingAnalyses } from './pendingAnalysis';
const sbom = '11111111-1111-4111-8111-111111111111';
const run = '22222222-2222-4222-8222-222222222222';
beforeEach(() => sessionStorage.clear());
it('retains a UUID SBOM recovery marker and its distinct UUID run identity', () => {
  addPendingAnalysis(sbom, 'Synthetic', 'tenant:user', run);
  clearStalePendingAnalyses();
  expect(getStillPendingAnalyses('tenant:user')).toMatchObject([{ sbomId: sbom, runId: run }]);
});
it('discards pre-cutover numeric SBOM recovery markers', () => {
  addPendingAnalysis(7, 'Legacy fixture', 'tenant:user', run);
  clearStalePendingAnalyses();
  expect(getStillPendingAnalyses('tenant:user')).toEqual([]);
});
it.each([7, '7', 'not-a-uuid', '00000000-0000-1000-8000-000000000001', '00000000-0000-4000-7000-000000000001'])('rejects non-public resource selector %s', value => {
  expect(publicId(value)).toBeNull();
});
it('UUID strings retain identity without numeric coercion', () => {
  expect(publicId(run.toUpperCase())).toBe(run);
  expect(Number.isNaN(Number(run))).toBe(true);
});
