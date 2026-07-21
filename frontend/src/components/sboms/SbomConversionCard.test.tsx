// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

import { SbomConversionCard } from '@/components/sboms/SbomConversionCard';
import type { SBOMSource } from '@/types';

const convertSbomToCycloneDX = vi.fn();
const exportSbomDocument = vi.fn();
const getSbomConversionReport = vi.fn();
const getSbom = vi.fn();
const invalidateSbomConversionSurfaces = vi.fn();

vi.mock('@/lib/queryInvalidation', () => ({
  invalidateSbomConversionSurfaces: (...args: unknown[]) => invalidateSbomConversionSurfaces(...args),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    convertSbomToCycloneDX: (...args: unknown[]) => convertSbomToCycloneDX(...args),
    exportSbomDocument: (...args: unknown[]) => exportSbomDocument(...args),
    getSbomConversionReport: (...args: unknown[]) => getSbomConversionReport(...args),
    getSbom: (...args: unknown[]) => getSbom(...args),
  };
});

function wrapper(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}><ToastProvider>{children}</ToastProvider></QueryClientProvider>;
}

const spdxSbom: SBOMSource = {
  id: 42,
  sbom_name: 'test-spdx',
  sbom_type: 1,
  sbom_version: '1.0.0',
  projectid: null,
  created_by: 'tester',
  created_on: '2026-06-17T00:00:00Z',
  modified_by: null,
  modified_on: null,
  productver: null,
  format: 'spdx',
  status: 'validated',
};

const cdxSbom: SBOMSource = {
  ...spdxSbom,
  id: 99,
  format: 'cyclonedx',
};

describe('SbomConversionCard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getSbomConversionReport.mockRejectedValue(new Error('not found'));
    getSbom.mockResolvedValue({ ...spdxSbom, enrichment_status: 'pending' });
  });

  it('shows Convert to CycloneDX button for SPDX SBOMs', () => {
    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    expect(screen.getByRole('button', { name: /Convert to CycloneDX/i })).toBeInTheDocument();
  });

  it('does not render for non-SPDX SBOMs', () => {
    const { container } = render(wrapper(<SbomConversionCard sbom={cdxSbom} formatLabel="CycloneDX" />));
    expect(container).toBeEmptyDOMElement();
  });

  it('calls convert API when clicking convert', async () => {
    convertSbomToCycloneDX.mockResolvedValue({
      source_sbom_id: 42,
      converted_sbom_id: 100,
      source_format: 'SPDX',
      target_format: 'CycloneDX',
      status: 'completed',
      conversion_status: 'completed',
      enrichment_status: 'pending',
      message: 'Converted to CycloneDX. Lifecycle enrichment is running in background.',
      warnings: [],
      errors: [],
      conversion_report: {},
    });

    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    fireEvent.click(screen.getByRole('button', { name: /Convert to CycloneDX/i }));

    await waitFor(() => {
      expect(convertSbomToCycloneDX).toHaveBeenCalledWith(42);
    });
  });

  it('shows converted SBOM link and background enrichment message on success', async () => {
    convertSbomToCycloneDX.mockResolvedValue({
      source_sbom_id: 42,
      converted_sbom_id: 100,
      source_format: 'SPDX',
      target_format: 'CycloneDX',
      status: 'completed',
      conversion_status: 'completed',
      enrichment_status: 'pending',
      message: 'Converted to CycloneDX. Lifecycle enrichment is running in background.',
      warnings: [],
      errors: [],
      conversion_report: {},
    });

    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    fireEvent.click(screen.getByRole('button', { name: /Convert to CycloneDX/i }));

    await waitFor(() => {
      expect(screen.getByRole('link', { name: '#100' })).toBeInTheDocument();
      expect(screen.getByText(/running in background/i)).toBeInTheDocument();
      expect(screen.getByText(/Enrichment pending/i)).toBeInTheDocument();
    });
  });

  it('uses narrow query invalidation after conversion', async () => {
    convertSbomToCycloneDX.mockResolvedValue({
      source_sbom_id: 42,
      converted_sbom_id: 100,
      source_format: 'SPDX',
      target_format: 'CycloneDX',
      status: 'completed',
      conversion_status: 'completed',
      enrichment_status: 'pending',
      message: 'Converted to CycloneDX. Lifecycle enrichment is running in background.',
      warnings: [],
      errors: [],
      conversion_report: {},
    });

    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    fireEvent.click(screen.getByRole('button', { name: /Convert to CycloneDX/i }));

    await waitFor(() => {
      expect(invalidateSbomConversionSurfaces).toHaveBeenCalled();
    });
  });

  it('shows export buttons when conversion exists', () => {
    render(
      wrapper(
        <SbomConversionCard
          sbom={{
            ...spdxSbom,
            converted_sbom_id: 100,
            conversion_status: 'completed_with_warnings',
            enrichment_status: 'pending',
          }}
          formatLabel="SPDX"
        />,
      ),
    );
    expect(screen.getByRole('button', { name: /Export Original SPDX/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export Converted CycloneDX/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export Enriched CycloneDX/i })).toBeInTheDocument();
  });

  it('shows conversion failure message from mutation error', async () => {
    convertSbomToCycloneDX.mockRejectedValue(new Error('Conversion failed: invalid SPDX'));

    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    fireEvent.click(screen.getByRole('button', { name: /Convert to CycloneDX/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/SBOM conversion failed\. Please try again\./i).length).toBeGreaterThan(0);
    });
  });

  it('shows clear timeout error message', async () => {
    convertSbomToCycloneDX.mockRejectedValue(new Error('Request timed out after 30000ms'));

    render(wrapper(<SbomConversionCard sbom={spdxSbom} formatLabel="SPDX" />));
    fireEvent.click(screen.getByRole('button', { name: /Convert to CycloneDX/i }));

    await waitFor(() => {
      expect(screen.getByText(/Conversion timed out/i)).toBeInTheDocument();
    });
  });

  it('downloads original SPDX export', async () => {
    exportSbomDocument.mockResolvedValue({ blob: new Blob(['{}']), filename: 'original.spdx.json' });

    render(
      wrapper(
        <SbomConversionCard
          sbom={{ ...spdxSbom, converted_sbom_id: 100, conversion_status: 'completed' }}
          formatLabel="SPDX"
        />,
      ),
    );

    fireEvent.click(screen.getByRole('button', { name: /Export Original SPDX/i }));

    await waitFor(() => {
      expect(exportSbomDocument).toHaveBeenCalledWith(42, {
        format: 'spdx',
        exportMode: 'original',
      });
    });
  });
});
