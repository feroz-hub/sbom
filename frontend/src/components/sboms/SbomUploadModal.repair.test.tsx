// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpError } from '@/lib/api';

const push = vi.fn();
const useUploadSbomMutate = vi.fn();
const showToast = vi.fn();
const getSbomTypes = vi.fn();

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
}));

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
    getSbomTypes: (...args: unknown[]) => getSbomTypes(...args),
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
  push.mockReset();
  useUploadSbomMutate.mockReset();
  showToast.mockReset();
  getSbomTypes.mockReset();
  getSbomTypes.mockResolvedValue([]);
  vi.restoreAllMocks();
});

async function fillRequiredFieldsAndSubmit(name: string, content = '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}') {
  expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: name } });
  fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
  fireEvent.change(screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview'), {
    target: { value: content },
  });
  fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));
}

describe('SbomUploadModal validation repair handoff', () => {
  it('defaults the format selector to Auto-detect', async () => {
    getSbomTypes.mockResolvedValue([
      { id: 1, typename: 'CycloneDX JSON' },
      { id: 2, typename: 'SPDX JSON' },
    ]);

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    const formatSelect = await screen.findByLabelText(/SBOM Type \/ Format/i);
    expect(formatSelect).toHaveValue('');
    expect(screen.getByRole('option', { name: 'Auto-detect' })).toBeInTheDocument();
  });

  it('detects SPDX JSON content and selects the matching SPDX type', async () => {
    getSbomTypes.mockResolvedValue([
      { id: 1, typename: 'CycloneDX JSON' },
      { id: 2, typename: 'SPDX JSON' },
    ]);

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    const editor = screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview');
    fireEvent.change(editor, {
      target: {
        value: '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}',
      },
    });

    expect(await screen.findByText(/SPDX JSON SPDX-2.3/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText(/SBOM Type \/ Format/i)).toHaveValue('2'));
  });

  it('does not default unknown JSON to CycloneDX', async () => {
    getSbomTypes.mockResolvedValue([
      { id: 1, typename: 'CycloneDX JSON' },
      { id: 2, typename: 'SPDX JSON' },
    ]);

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    fireEvent.change(screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview'), {
      target: { value: '{"ok":false,"dependencyCount":10052}' },
    });

    expect(await screen.findByText(/Format could not be detected automatically/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/SBOM Type \/ Format/i)).toHaveValue('');
  });

  it('does not send a CycloneDX type by default', async () => {
    getSbomTypes.mockResolvedValue([
      { id: 1, typename: 'CycloneDX JSON' },
      { id: 2, typename: 'SPDX JSON' },
    ]);
    useUploadSbomMutate.mockImplementation((_payload, _handlers) => {});

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'unknown-sbom' } });
    fireEvent.change(screen.getByLabelText(/Project/i), { target: { value: '42' } });
    fireEvent.change(screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview'), {
      target: { value: '{"ok":false}' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    await waitFor(() => expect(useUploadSbomMutate).toHaveBeenCalled());
    expect(useUploadSbomMutate.mock.calls[0][0].sbom_type).toBeUndefined();
  });

  it('closes valid uploads, refreshes upload surfaces, and does not open repair workspace', async () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();
    const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries');
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

    await fillRequiredFieldsAndSubmit('good-sbom');

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'SBOM uploaded and validated successfully.',
        'success',
        { duration: 5000 },
      );
    });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSuccess).toHaveBeenCalledWith(expect.objectContaining({ id: 7, enrichment_status: 'pending' }));
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['sboms'] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['dashboard-posture'] });
    expect(push).not.toHaveBeenCalled();
    expect(screen.queryByText(/Upload stored and validated/i)).not.toBeInTheDocument();
  });

  it('closes warning uploads, refreshes upload surfaces, and does not open repair workspace', async () => {
    const onClose = vi.fn();
    const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries');
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

    render(wrap(<SbomUploadModal open onClose={onClose} />));

    await fillRequiredFieldsAndSubmit('warning-sbom');

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'SBOM uploaded with validation warnings.',
        'success',
        { duration: 5000 },
      );
    });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['sboms'] });
    expect(push).not.toHaveBeenCalled();
    expect(screen.queryByRole('link', { name: /Review \/ Repair Workspace/i })).not.toBeInTheDocument();
  });

  it('shows upload timeout or network errors without opening repair workspace', async () => {
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(new Error('Request timed out after 120000ms'));
    });

    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    await fillRequiredFieldsAndSubmit('slow-sbom');

    expect(await screen.findByText('Request timed out after 120000ms')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });

  it('closes failed uploads and opens repair workspace automatically', async () => {
    const onClose = vi.fn();
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

    render(wrap(<SbomUploadModal open onClose={onClose} />));

    await fillRequiredFieldsAndSubmit('bad-sbom', '{"bad":true}');

    await waitFor(() => expect(useUploadSbomMutate).toHaveBeenCalledWith(
      expect.objectContaining({ projectid: 42, project_id: 42 }),
      expect.any(Object),
    ));
    expect(showToast).toHaveBeenCalledWith(
      'SBOM validation failed. Opening Repair Workspace.',
      'error',
      { duration: 6000 },
    );
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(push).toHaveBeenCalledWith('/repair/repair-123');
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });

  it('closes unsupported uploads and opens repair workspace automatically', async () => {
    const onClose = vi.fn();
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

    render(wrap(<SbomUploadModal open onClose={onClose} />));

    await fillRequiredFieldsAndSubmit('unsupported-sbom', '{"not":"sbom"}');

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'SBOM format could not be detected or is unsupported. Opening Repair Workspace.',
        'error',
        { duration: 6000 },
      );
    });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(push).toHaveBeenCalledWith('/repair/unsupported-workspace-1');
    expect(screen.queryByRole('link', { name: /Open Workspace/i })).not.toBeInTheDocument();
  });

  it('constructs the repair URL from workspace_id when failed response omits repair_workspace_url', async () => {
    const onClose = vi.fn();
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      handlers.onError(
        new HttpError('validation failed', 422, 'sbom_validation_failed', {
          status: 'validation_failed',
          message: 'Validation failed',
          sbom_id: null,
          workspace_id: 'workspace-fallback-1',
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

    render(wrap(<SbomUploadModal open onClose={onClose} />));

    await fillRequiredFieldsAndSubmit('bad-sbom', '{"bad":true}');

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    expect(push).toHaveBeenCalledWith('/repair/workspace-fallback-1');
  });

  it('handles an upload result only once', async () => {
    const onClose = vi.fn();
    useUploadSbomMutate.mockImplementation((_payload, handlers) => {
      const result = {
        id: 9,
        sbom_name: 'single-result-sbom',
        projectid: 42,
        project_id: 42,
        project_name: 'Payments',
        component_count: 1,
        status: 'validated',
        validation_status: 'valid',
        upload_status: 'valid',
        workspace_id: 'single-workspace-1',
        validation_session_id: 'single-workspace-1',
        repair_workspace_url: '/repair/single-workspace-1',
        enrichment_status: 'pending',
      };
      handlers.onSuccess(result);
      handlers.onSuccess(result);
    });

    render(wrap(<SbomUploadModal open onClose={onClose} />));

    await fillRequiredFieldsAndSubmit('single-result-sbom');

    await waitFor(() => expect(showToast).toHaveBeenCalledTimes(1));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(push).not.toHaveBeenCalled();
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
    fireEvent.change(screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview'), { target: { value: '{"bad":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Upload SBOM/i }));

    expect(await screen.findByText('Payload blocked by security validation')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open repair workspace/i })).not.toBeInTheDocument();
  });

  it('requires a project before allowing upload', async () => {
    render(wrap(<SbomUploadModal open onClose={vi.fn()} />));

    fireEvent.change(screen.getByLabelText(/SBOM Name/i), { target: { value: 'needs-project' } });
    fireEvent.change(screen.getByPlaceholderText('Paste a small SPDX, CycloneDX, or XML SBOM preview'), { target: { value: '{"bomFormat":"CycloneDX"}' } });

    expect(await screen.findByRole('button', { name: /Upload SBOM/i })).toBeDisabled();
    expect(useUploadSbomMutate).not.toHaveBeenCalled();
  });
});
