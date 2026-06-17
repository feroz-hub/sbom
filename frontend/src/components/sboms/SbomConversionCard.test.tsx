// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SbomConversionCard } from '@/components/sboms/SbomConversionCard';
import type { SBOMSource } from '@/types';

const convertSbomToCycloneDX = vi.fn();
const exportSbomDocument = vi.fn();
const getSbomConversionReport = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    convertSbomToCycloneDX: (...args: unknown[]) => convertSbomToCycloneDX(...args),
    exportSbomDocument: (...args: unknown[]) => exportSbomDocument(...args),
    getSbomConversionReport: (...args: unknown[]) => getSbomConversionReport(...args),
  };
});

function wrapper(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
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

  it('shows converted SBOM link after conversion', () => {
    render(
      wrapper(
        <SbomConversionCard
          sbom={{
            ...spdxSbom,
            converted_sbom_id: 100,
            conversion_status: 'completed',
          }}
          formatLabel="SPDX"
        />,
      ),
    );
    expect(screen.getByRole('link', { name: '#100' })).toHaveAttribute('href', '/sboms/100');
  });

  it('shows export buttons when conversion exists', () => {
    render(
      wrapper(
        <SbomConversionCard
          sbom={{
            ...spdxSbom,
            converted_sbom_id: 100,
            conversion_status: 'completed_with_warnings',
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
      expect(screen.getByText(/Conversion failed: invalid SPDX/i)).toBeInTheDocument();
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
