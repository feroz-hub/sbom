// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpError } from '@/lib/api';

const useUploadSbomMutate = vi.fn();
const showToast = vi.fn();

vi.mock('@/hooks/useSbomMutations', () => ({
  useUploadSbom: () => ({ mutate: useUploadSbomMutate, isPending: false }),
}));

vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast }),
}));

vi.mock('@/hooks/useSbomsList', () => ({
  useSbomsList: () => ({ data: [] }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getProjects: vi.fn().mockResolvedValue([
      {
        id: 42,
        project_name: 'Payments',
        project_details: null,
        project_status: 1,
        created_by: null,
        created_on: null,
        modified_by: null,
        modified_on: null,
      },
    ]),
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
  showToast.mockReset();
});

describe('SbomUploadModal validation repair handoff', () => {
  it('shows upload success copy that enrichment continues in background', async () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onSuccess({
        id: 7,
        sbom_name: 'good-sbom',
        projectid: 42,
        project_id: 42,
        project_name: 'Payments',
        component_count: 1,
        status: 'validated',
        validation_status: 'valid',
        workspace_id: 'valid-workspace-1',
        validation_session_id: 'valid-workspace-1',
        repair_workspace_url: '/repair/valid-workspace-1',
        enrichment_status: 'pending',
      });
    });

    render(wrap(<SbomUploadModal open onClose={onClose} onSuccess={onSuccess} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'good-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), {
      target: { value: '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        '"good-sbom" uploaded successfully. Enrichment is running in background.',
        'success',
        { duration: 5000 },
      );
    });
    expect(onClose).not.toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalledWith(expect.objectContaining({ id: 7, enrichment_status: 'pending' }));
    expect(screen.getByRole('link', { name: /Open Repair Workspace/i })).toHaveAttribute(
      'href',
      '/repair/valid-workspace-1',
    );
  });

  it('shows a Review / Repair Workspace link for valid uploads with warnings', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onSuccess({
        id: 8,
        sbom_name: 'warning-sbom',
        projectid: 42,
        project_id: 42,
        project_name: 'Payments',
        component_count: 1,
        status: 'validated',
        validation_status: 'valid_with_warnings',
        upload_status: 'valid_with_warnings',
        workspace_id: 'warning-workspace-1',
        validation_session_id: 'warning-workspace-1',
        repair_workspace_url: '/repair/warning-workspace-1',
        enrichment_status: 'pending',
      });
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'warning-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), {
      target: { value: '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByRole('link', { name: /Review \/ Repair Workspace/i })).toHaveAttribute(
      'href',
      '/repair/warning-workspace-1',
    );
  });

  it('shows upload timeout or network errors without opening repair workspace', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(new Error('Request timed out after 120000ms'));
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'slow-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), {
      target: { value: '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByText('Request timed out after 120000ms')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });

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

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'bad-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    await waitFor(() => expect(useUploadSbomMutate).toHaveBeenCalledWith(
      expect.objectContaining({ projectid: 42, project_id: 42 }),
      expect.any(Object),
    ));
    const link = await screen.findByRole('link', { name: /Open repair workspace/i });
    expect(link).toHaveAttribute('href', '/repair/repair-123');
  });

  it('shows an Open Workspace link for unsupported uploads with a workspace session', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(
        new HttpError('unsupported format', 415, 'unsupported_sbom_format', {
          status: 'unsupported_format',
          message: 'Format could not be detected.',
          sbom_id: null,
          workspace_id: 'unsupported-workspace-1',
          validation_session_id: 'unsupported-workspace-1',
          repair_workspace_url: '/repair/unsupported-workspace-1',
          can_edit: true,
          can_ai_fix: false,
          error_count: 1,
          warning_count: 0,
          entries: [],
          truncated: false,
        }),
      );
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'unsupported-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"not":"sbom"}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByRole('link', { name: /Open Workspace/i })).toHaveAttribute(
      'href',
      '/repair/unsupported-workspace-1',
    );
  });

  it('shows the repair link when the backend returns a session without can_edit', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(
        new HttpError('validation failed', 422, 'sbom_validation_failed', {
          status: 'validation_failed',
          message: 'Validation failed',
          sbom_id: null,
          session_id: 'repair-no-can-edit',
          failed_stage: 'semantic',
          error_count: 1,
          warning_count: 0,
          error_report: {
            status: 'failed',
            failed_stage: 'semantic',
            error_count: 1,
            warning_count: 0,
            info_count: 0,
            truncated: false,
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
          },
          truncated: false,
        }),
      );
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'bad-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    const link = await screen.findByRole('link', { name: /Open repair workspace/i });
    expect(link).toHaveAttribute('href', '/repair/repair-no-can-edit');
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

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'blocked-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByText('Payload blocked by security validation')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });

  it('requires a project before allowing upload', async () => {
    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'needs-project' } });
    fireEvent.change(screen.getByPlaceholderText('{"bomFormat": "CycloneDX", ...}'), { target: { value: '{"bomFormat":"CycloneDX"}' } });

    expect(await screen.findByRole('button', { name: /Upload SBOM/i })).toBeDisabled();
    expect(useUploadSbomMutate).not.toHaveBeenCalled();
  });
});
