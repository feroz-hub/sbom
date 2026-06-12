// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpError } from '@/lib/api';

const useUploadSbomMutate = vi.fn();

vi.mock('@/hooks/useSbomMutations', () => ({
  useUploadSbom: () => ({ mutate: useUploadSbomMutate, isPending: false }),
}));

vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast: vi.fn() }),
}));

vi.mock('@/hooks/useSbomsList', () => ({
  useSbomsList: () => ({ data: [] }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getProjects: vi.fn().mockResolvedValue([]),
    getSbomTypes: vi.fn().mockResolvedValue([]),
  };
});

import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  useUploadSbomMutate.mockReset();
});

describe('SbomUploadModal validation repair handoff', () => {
  it('shows an Open repair workspace link when upload validation creates a session', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(
        new HttpError('validation failed', 422, 'sbom_validation_failed', {
          code: 'sbom_validation_failed',
          status: 'validation_failed',
          message: 'Validation failed',
          sbom_id: null,
          session_id: 'repair-123',
          can_edit: true,
          can_ai_fix: true,
          failed_stage: 'semantic',
          error_count: 1,
          warning_count: 0,
          entries: [
            {
              code: 'SBOM_VAL_E052_PURL_INVALID',
              severity: 'error',
              stage: 'semantic',
              path: 'components[0].purl',
              message: 'Bad purl',
              remediation: 'Fix purl',
              spec_reference: null,
            },
          ],
          truncated: false,
        }),
      );
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'bad-sbom' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    await waitFor(() => expect(useUploadSbomMutate).toHaveBeenCalled());
    const link = await screen.findByRole('link', { name: /Open repair workspace/i });
    expect(link).toHaveAttribute('href', '/sbom-validation-sessions/repair-123');
  });

  it('shows security-blocked text when no repair session is created', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(
        new HttpError('validation failed', 400, 'sbom_validation_failed', {
          code: 'sbom_validation_failed',
          status: 'validation_failed',
          message: 'Validation failed',
          sbom_id: null,
          session_id: null,
          can_edit: false,
          can_ai_fix: false,
          reason: 'Payload blocked by security validation',
          failed_stage: 'ingress',
          error_count: 1,
          warning_count: 0,
          entries: [
            {
              code: 'SBOM_VAL_E080_JSON_DEPTH_EXCEEDED',
              severity: 'error',
              stage: 'detect',
              path: '',
              message: 'Too deep',
              remediation: 'Reduce depth',
              spec_reference: null,
            },
          ],
          truncated: false,
        }),
      );
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'blocked-sbom' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByText('Payload blocked by security validation')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });
});
