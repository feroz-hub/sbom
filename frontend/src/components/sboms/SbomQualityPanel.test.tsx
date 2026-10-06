// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { SbomQualityCard, SbomQualityPanel } from './SbomQualityPanel';
import { getSessionQuality } from '@/lib/api';
import type { QualityAssessment, QualityComparison } from '@/types/sbomQuality';
vi.mock('@/lib/api', () => ({ getSessionQuality: vi.fn(), getSbomQuality: vi.fn() }));
const assessment: QualityAssessment = {
  overall_score: 72.4, grade: 'FAIR', dimensions: [{ code: 'QD-07', name: 'License Completeness', score: 0, weight: 7.5, finding_count: 1, metrics: { eligible: 1 } }],
  findings: [{ code: 'QUALITY_LICENSES_MISSING', dimension: 'QD-07', severity: 'MINOR', path: '/components/0/licenses', message: 'Eligible component has missing licenses.', remediation: 'Provide verified metadata; unknown values cannot be invented.', repairable: false, repairability_assessed: true, repair_classification: 'MANUAL_ONLY', quality_impact: 100 }],
  calculated_at: '2026-10-06T00:00:00Z', engine_version: '2.0.0', artifact_hash: 'a'.repeat(64), configuration_hash: 'b'.repeat(64), spec_version: '1.6', validation_status: 'PASSED', supported: true, reason: null, findings_truncated: false,
};
const comparison: QualityComparison = { before: assessment, after: { ...assessment, overall_score: 86.4 }, comparable: true, improvement: 14, dimensions: [{ code: 'QD-02', name: 'Identifier Integrity', before: 50, after: 100, improvement: 50 }] };
function panel() { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SbomQualityPanel sessionId="quality-session" /></QueryClientProvider>); }
beforeEach(() => { vi.clearAllMocks(); vi.mocked(getSessionQuality).mockResolvedValue({ enabled: true, assessment }); });
describe('advisory quality', () => {
  it('renders a rounded summary and grade independently of validation', () => {
    render(<SbomQualityCard assessment={assessment} />);
    expect(screen.getByText('72 / 100')).toBeInTheDocument();
    expect(screen.getByText('fair')).toBeInTheDocument();
    expect(screen.getByText(/Validation: PASSED/)).toBeInTheDocument();
    expect(screen.getByText('License Completeness')).toBeInTheDocument();
  });
  it('shows missing license finding as manual and does not invent a repair', () => {
    render(<SbomQualityCard assessment={assessment} />);
    fireEvent.click(screen.getByRole('button', { name: 'View Quality Findings' }));
    expect(screen.getByText(/Not available — manual review/)).toBeInTheDocument();
    expect(screen.getByText('/components/0/licenses')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Auto-Repair Safe Issues' })).not.toBeInTheDocument();
  });
  it('shows repairable findings and an explicit analysis limit', () => {
    render(<SbomQualityCard assessment={{ ...assessment, findings: [{ ...assessment.findings[0], repairable: true }, { ...assessment.findings[0], code: 'unassessed', repairability_assessed: false }] }} />);
    fireEvent.click(screen.getByRole('button', { name: 'View Quality Findings' }));
    expect(screen.getByText('Auto-Repair: Available for review')).toBeInTheDocument();
    expect(screen.getByText('Auto-Repair: Analysis required')).toBeInTheDocument();
  });
  it('binds before/after comparison to actual candidate data', () => {
    render(<SbomQualityCard assessment={comparison.after} comparison={comparison} />);
    expect(screen.getByText('Before: 72.4 · After: 86.4')).toBeInTheDocument();
    expect(screen.getByText('Change: +14 points')).toBeInTheDocument();
    expect(screen.getByText('Identifier Integrity: 50 → 100')).toBeInTheDocument();
  });
  it('keeps a partial repair visibly failed regardless of score gain', () => {
    render(<SbomQualityCard assessment={{ ...assessment, validation_status: 'FAILED' }} comparison={{ ...comparison, after: { ...comparison.after, validation_status: 'FAILED' } }} />);
    expect(screen.getByText(/Candidate validation: FAILED/)).toBeInTheDocument();
    expect(screen.queryByText('Repair successful')).not.toBeInTheDocument();
  });
  it('labels stale comparison', () => {
    render(<SbomQualityCard assessment={assessment} comparison={comparison} stale />);
    expect(screen.getByText(/earlier draft/)).toBeInTheDocument();
  });
  it('does not compare mismatched scoring policies', () => {
    render(<SbomQualityCard assessment={assessment} comparison={{ ...comparison, comparable: false, improvement: null, dimensions: [] }} />);
    expect(screen.getByText(/cannot be compared/)).toBeInTheDocument();
    expect(screen.queryByText(/Change:/)).not.toBeInTheDocument();
  });
  it('shows non-applicable dimensions without a misleading coverage claim', () => {
    render(<SbomQualityCard assessment={{ ...assessment, dimensions: [{ ...assessment.dimensions[0], metrics: { eligible: 0 }, score: 100 }] }} />);
    expect(screen.getByText('Not applicable')).toBeInTheDocument();
  });
  it('shows loading followed by quality fetched for the current session', async () => {
    panel();
    expect(screen.getByRole('status')).toHaveTextContent('Calculating SBOM quality');
    expect(await screen.findByText('SBOM Quality')).toBeInTheDocument();
    expect(getSessionQuality).toHaveBeenCalledWith('quality-session', expect.any(AbortSignal));
  });
  it('keeps validation available on API failure', async () => {
    vi.mocked(getSessionQuality).mockRejectedValue(new Error('unavailable'));
    panel();
    expect(await screen.findByText(/Existing validation and repair remain available/)).toBeInTheDocument();
  });
  it('hides disabled quality scoring', async () => {
    vi.mocked(getSessionQuality).mockResolvedValue({ enabled: false, assessment: null });
    panel();
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    expect(screen.queryByText('SBOM Quality')).not.toBeInTheDocument();
  });
  it('explains unsupported formats without a numeric zero grade', () => {
    render(<SbomQualityCard assessment={{ ...assessment, supported: false, reason: 'CycloneDX JSON required.' }} />);
    expect(screen.getByText('CycloneDX JSON required.')).toBeInTheDocument();
    expect(screen.queryByText(/\/ 100/)).not.toBeInTheDocument();
  });
  it('escapes untrusted findings and uses responsive theme classes', () => {
    render(<SbomQualityCard assessment={{ ...assessment, findings: [{ ...assessment.findings[0], message: '<script>data</script>' }] }} />);
    fireEvent.click(screen.getByRole('button', { name: 'View Quality Findings' }));
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText(/<script>data<\/script>/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'SBOM Quality' }).className).toContain('dark:bg-slate-900');
    expect(document.querySelector('dl')?.className).toContain('sm:grid-cols-2');
  });
});

it('distinguishes limited report display from the approval completeness policy', () => {
  const limited = { ...assessment, validation_report_truncated: true };
  render(<SbomQualityCard assessment={limited} comparison={{ ...comparison, after: limited }} />);
  expect(screen.getByText(/Validation: PASSED/)).toBeInTheDocument();
  expect(screen.getByText(/Report limited — complete-validation approval policy applies/)).toBeInTheDocument();
});

it.each([0, -12.3])('faithfully renders a non-increasing candidate comparison (%s)', improvement => {
  const after = { ...assessment, overall_score: assessment.overall_score + improvement };
  render(<SbomQualityCard assessment={after} comparison={{ ...comparison, after, improvement, dimensions: [] }} />);
  expect(screen.getByText(`Change: ${improvement} points`)).toBeInTheDocument();
  expect(screen.getByText(`Before: ${assessment.overall_score} · After: ${after.overall_score}`)).toBeInTheDocument();
});

it.each([[89.9, 'GOOD', 'good'], [79.9, 'FAIR', 'fair'], [49.9, 'CRITICAL_QUALITY', 'critical quality']])(
  'uses the server grade rather than regrading the rounded score (%s)', (value, grade, label) => {
    render(<SbomQualityCard assessment={{ ...assessment, overall_score: Number(value), grade: String(grade) }} />);
    expect(screen.getByText(String(label))).toBeInTheDocument();
  }
);
