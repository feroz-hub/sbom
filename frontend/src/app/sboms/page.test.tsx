// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SBOMSource } from '@/types';

const triggerBackgroundAnalysis = vi.fn();

vi.mock('@/hooks/useBackgroundAnalysis', () => ({
  useBackgroundAnalysis: () => ({ triggerBackgroundAnalysis }),
}));

vi.mock('@/hooks/useSbomsList', () => ({
  useSbomsList: () => ({ data: [], isLoading: false, error: null }),
}));

vi.mock('@/components/layout/TopBar', () => ({
  TopBar: ({ action }: { action: ReactNode }) => <div>{action}</div>,
}));

vi.mock('@/components/sboms/SbomsTable', () => ({
  SbomsTable: () => <div>SBOM table</div>,
}));

vi.mock('@/components/sboms/SbomUploadModal', () => ({
  SbomUploadModal: ({
    open,
    onSuccess,
  }: {
    open: boolean;
    onSuccess?: (sbom: SBOMSource) => void;
  }) =>
    open ? (
      <button
        type="button"
        onClick={() =>
          onSuccess?.({
            id: 123,
            sbom_name: 'uploaded-sbom',
            status: 'validated',
            created_on: '2026-07-01T00:00:00Z',
          } as SBOMSource)
        }
      >
        Finish upload
      </button>
    ) : null,
}));

import SbomsPage from './page';

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe('SbomsPage upload success', () => {
  beforeEach(() => {
    triggerBackgroundAnalysis.mockReset();
  });

  it('does not start background analysis after upload', () => {
    render(wrap(<SbomsPage />));

    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));
    fireEvent.click(screen.getByRole('button', { name: /Finish upload/i }));

    expect(triggerBackgroundAnalysis).not.toHaveBeenCalled();
  });
});
