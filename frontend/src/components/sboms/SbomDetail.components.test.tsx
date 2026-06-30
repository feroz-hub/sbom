// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SBOMComponent, SBOMSource } from '@/types';

const back = vi.fn();
const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ back, push, replace: vi.fn() }),
}));

vi.mock('@/hooks/useAnalysisStream', () => ({
  useAnalysisStream: () => ({
    state: { phase: 'idle' },
    startAnalysis: vi.fn(),
    cancel: vi.fn(),
    reset: vi.fn(),
  }),
}));

vi.mock('@/components/schedules/ScheduleCard', () => ({
  ScheduleCard: () => null,
}));

vi.mock('@/components/sboms/ValidationReportSection', () => ({
  ValidationReportSection: () => null,
}));

vi.mock('@/components/sboms/SbomConversionCard', () => ({
  SbomConversionCard: () => null,
}));

const showToast = vi.fn();
vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast, updateToast: vi.fn() }),
}));

const getSbomComponents = vi.fn();
const getSbomDedupeReport = vi.fn();
const getRuns = vi.fn();
const getSbomInfo = vi.fn();
const getSbomRiskSummary = vi.fn();
const getSbomValidationReport = vi.fn();
const getSbomVersions = vi.fn();
const getSbomVexStatements = vi.fn();
const createWorkspaceForSbom = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getSbomComponents: (...args: unknown[]) => getSbomComponents(...args),
    getSbomDedupeReport: (...args: unknown[]) => getSbomDedupeReport(...args),
    getRuns: (...args: unknown[]) => getRuns(...args),
    getSbomInfo: (...args: unknown[]) => getSbomInfo(...args),
    getSbomRiskSummary: (...args: unknown[]) => getSbomRiskSummary(...args),
    getSbomValidationReport: (...args: unknown[]) => getSbomValidationReport(...args),
    getSbomVersions: (...args: unknown[]) => getSbomVersions(...args),
    getSbomVexStatements: (...args: unknown[]) => getSbomVexStatements(...args),
    createWorkspaceForSbom: (...args: unknown[]) => createWorkspaceForSbom(...args),
  };
});

import { SbomDetail } from './SbomDetail';

const SBOM: SBOMSource = {
  id: 42,
  sbom_name: 'dedupe-sbom',
  sbom_type: 1,
  projectid: null,
  created_on: '2026-06-01T00:00:00Z',
  sbom_version: '1.0.0',
  created_by: 'tester',
  productver: null,
  modified_on: null,
  modified_by: null,
  status: 'validated',
};

const CANONICAL: SBOMComponent = {
  id: 1,
  sbom_id: 42,
  name: 'lodash',
  version: '4.17.21',
  cpe: null,
  purl: 'pkg:npm/lodash@4.17.21',
  normalized_name: 'lodash',
  normalized_version: '4.17.21',
  normalized_purl: 'pkg:npm/lodash@4.17.21',
  primary_cpe: null,
  dedupe_confidence: 'High',
  component_type: 'library',
  scope: null,
  created_on: null,
  is_duplicate: false,
};

const DUPLICATE: SBOMComponent = {
  id: 2,
  sbom_id: 42,
  name: 'lodash',
  version: '4.17.21',
  cpe: null,
  purl: 'pkg:npm/lodash@4.17.21',
  component_type: 'library',
  scope: null,
  created_on: null,
  is_duplicate: true,
  duplicate_of_component_id: 1,
  canonical_component_name: 'lodash',
  canonical_component_version: '4.17.21',
  duplicate_reason: 'Duplicate SBOM component entry merged into the canonical component',
};

function wrap(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={client}>{ui}</QueryClientProvider>;
}

function listResponse(
  items: SBOMComponent[],
  options: Partial<{
    include_duplicates: boolean;
    unique_count: number;
    duplicate_count: number;
    total_count: number;
  }> = {},
) {
  return {
    items,
    total_count: options.total_count ?? items.length,
    unique_count: options.unique_count ?? items.filter((item) => !item.is_duplicate).length,
    duplicate_count: options.duplicate_count ?? items.filter((item) => item.is_duplicate).length,
    include_duplicates: options.include_duplicates ?? false,
    page: 1,
    page_size: 25,
  };
}

beforeEach(() => {
  getSbomDedupeReport.mockResolvedValue({
    duplicates_found: 1,
    duplicates_merged: 1,
    summary: {
      total_components: 2,
      canonical_components: 1,
      duplicate_components: 1,
      duplicate_groups: 1,
      normalized_purls: 1,
    },
    duplicate_groups: [
      {
        group_id: 'group-1',
        normalized_component_key: 'purl:pkg:npm/lodash@4.17.21',
        canonical_ref: 'ref-lodash-1',
        duplicate_refs: ['ref-lodash-2'],
        confidence: 'High',
        reason: 'same_normalized_purl',
      },
    ],
    conflicts: [],
    ref_mapping: { 'ref-lodash-2': 'ref-lodash-1' },
    remapped_dependencies: {},
  });
  getRuns.mockResolvedValue([]);
  getSbomInfo.mockResolvedValue(null);
  getSbomRiskSummary.mockResolvedValue(null);
  getSbomValidationReport.mockResolvedValue(null);
  getSbomVersions.mockResolvedValue([]);
  getSbomVexStatements.mockResolvedValue({ sbom_id: 42, statements: [] });
  createWorkspaceForSbom.mockReset();
  push.mockReset();
});

describe('SbomDetail components list', () => {
  it('shows repair workspace actions for imported SBOMs with a workspace id', async () => {
    getSbomComponents.mockResolvedValue(listResponse([CANONICAL]));

    render(
      wrap(
        <SbomDetail
          sbom={{
            ...SBOM,
            workspace_id: 'imported-workspace-1',
            validation_session_id: 'imported-workspace-1',
            repair_workspace_url: '/repair/imported-workspace-1',
            validation_status: 'imported',
          }}
        />,
      ),
    );

    const detailButton = await screen.findByRole('button', { name: /Open Repair Workspace/i });
    expect(screen.getByRole('button', { name: /Open Workspace/i })).toBeInTheDocument();
    fireEvent.click(detailButton);
    expect(push).toHaveBeenCalledWith('/repair/imported-workspace-1');
  });

  it.each([
    ['valid', 'Open Repair Workspace'],
    ['valid_with_warnings', 'Review / Repair Workspace'],
  ])('shows repair workspace actions for %s SBOMs with a workspace id', async (validationStatus, label) => {
    getSbomComponents.mockResolvedValue(listResponse([CANONICAL]));

    render(
      wrap(
        <SbomDetail
          sbom={{
            ...SBOM,
            workspace_id: `${validationStatus}-workspace-1`,
            validation_session_id: `${validationStatus}-workspace-1`,
            repair_workspace_url: `/repair/${validationStatus}-workspace-1`,
            validation_status: validationStatus,
          }}
        />,
      ),
    );

    const detailButton = await screen.findByRole('button', { name: label });
    fireEvent.click(detailButton);
    expect(push).toHaveBeenCalledWith(`/repair/${validationStatus}-workspace-1`);
  });

  it('creates a workspace for backfillable validated SBOMs before navigating', async () => {
    getSbomComponents.mockResolvedValue(listResponse([CANONICAL]));
    createWorkspaceForSbom.mockResolvedValue({
      workspace_id: 'created-workspace-1',
      repair_workspace_url: '/repair/created-workspace-1',
    });

    render(
      wrap(
        <SbomDetail
          sbom={{
            ...SBOM,
            workspace_available: true,
            workspace_source: 'backfillable',
            validation_status: 'validated',
            detected_format: 'cyclonedx_json',
            detected_spec_version: '1.5',
          }}
        />,
      ),
    );

    expect(await screen.findByText('CycloneDX JSON 1.5')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Create\/Open Workspace/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Create\/Open Repair Workspace/i }));

    await waitFor(() => expect(createWorkspaceForSbom).toHaveBeenCalledWith(42));
    expect(push).toHaveBeenCalledWith('/repair/created-workspace-1');
  });

  it('shows an unavailable repair workspace message when original content is missing', async () => {
    getSbomComponents.mockResolvedValue(listResponse([CANONICAL]));

    render(
      wrap(
        <SbomDetail
          sbom={{
            ...SBOM,
            workspace_available: false,
            workspace_source: 'unavailable',
            workspace_unavailable_reason: 'Original SBOM content is not available for this legacy record.',
          }}
        />,
      ),
    );

    expect(await screen.findByText(/Repair Workspace unavailable/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Open Repair Workspace/i })).not.toBeInTheDocument();
  });

  it('hides duplicate rows by default and shows duplicate counts', async () => {
    getSbomComponents.mockImplementation((_sbomId: number, options?: { includeDuplicates?: boolean }) =>
      Promise.resolve(
        listResponse(options?.includeDuplicates ? [CANONICAL, DUPLICATE] : [CANONICAL], {
          unique_count: 1,
          duplicate_count: 1,
          total_count: options?.includeDuplicates ? 2 : 1,
          include_duplicates: Boolean(options?.includeDuplicates),
        }),
      ),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));

    expect(await screen.findByText(/1 unique/)).toBeInTheDocument();
    expect(screen.getByText(/Duplicates hidden: 1/)).toBeInTheDocument();
    expect(screen.queryByText('Duplicate')).not.toBeInTheDocument();
    expect(getSbomComponents).toHaveBeenCalledWith(
      42,
      expect.objectContaining({ includeDuplicates: false }),
    );
  });

  it('shows Show Duplicates button when duplicate_count > 0', async () => {
    getSbomComponents.mockResolvedValue(
      listResponse([CANONICAL], { unique_count: 1, duplicate_count: 1, total_count: 1 }),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));

    expect(await screen.findByRole('button', { name: 'Show Duplicates' })).toBeInTheDocument();
  });

  it('loads duplicates when Show Duplicates is clicked and marks duplicate rows', async () => {
    getSbomComponents.mockImplementation((_sbomId: number, options?: { includeDuplicates?: boolean }) =>
      Promise.resolve(
        listResponse(options?.includeDuplicates ? [CANONICAL, DUPLICATE] : [CANONICAL], {
          unique_count: 1,
          duplicate_count: 1,
          total_count: options?.includeDuplicates ? 2 : 1,
          include_duplicates: Boolean(options?.includeDuplicates),
        }),
      ),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    fireEvent.click(await screen.findByRole('button', { name: 'Show Duplicates' }));

    await waitFor(() =>
      expect(getSbomComponents).toHaveBeenCalledWith(
        42,
        expect.objectContaining({ includeDuplicates: true }),
      ),
    );
    expect(await screen.findByText('Duplicate')).toBeInTheDocument();
    expect(screen.getByText(/Duplicate of lodash 4\.17\.21/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hide Duplicates' })).toBeInTheDocument();
  });

  it('renders normalization summary and duplicate groups', async () => {
    getSbomComponents.mockResolvedValue(
      listResponse([CANONICAL], { unique_count: 1, duplicate_count: 1, total_count: 1 }),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Normalization/i }));

    expect(await screen.findByText('Stage 9 component identity and duplicate evidence.')).toBeInTheDocument();
    expect(screen.getByText('Canonical')).toBeInTheDocument();
    expect(await screen.findByText('ref-lodash-1')).toBeInTheDocument();
    expect(screen.getByText('same_normalized_purl')).toBeInTheDocument();
  });

  it('hides duplicates again when Hide Duplicates is clicked', async () => {
    getSbomComponents.mockImplementation((_sbomId: number, options?: { includeDuplicates?: boolean }) =>
      Promise.resolve(
        listResponse(options?.includeDuplicates ? [CANONICAL, DUPLICATE] : [CANONICAL], {
          unique_count: 1,
          duplicate_count: 1,
          total_count: options?.includeDuplicates ? 2 : 1,
          include_duplicates: Boolean(options?.includeDuplicates),
        }),
      ),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    fireEvent.click(await screen.findByRole('button', { name: 'Show Duplicates' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Hide Duplicates' }));

    await waitFor(() =>
      expect(getSbomComponents).toHaveBeenLastCalledWith(
        42,
        expect.objectContaining({ includeDuplicates: false }),
      ),
    );
  });

  it('passes search to the API in both duplicate modes', async () => {
    getSbomComponents.mockResolvedValue(
      listResponse([CANONICAL], { unique_count: 1, duplicate_count: 1, total_count: 1 }),
    );

    render(wrap(<SbomDetail sbom={SBOM} />));
    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    fireEvent.change(screen.getByLabelText('Search SBOM components'), {
      target: { value: 'lodash' },
    });

    await waitFor(() =>
      expect(getSbomComponents).toHaveBeenCalledWith(
        42,
        expect.objectContaining({ search: 'lodash', includeDuplicates: false }),
      ),
    );
  });
});
