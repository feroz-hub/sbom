// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SBOMSource, ValidationRepairSession } from '@/types';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
}));

const getValidationRepairSession = vi.fn();
const getValidationRepairContent = vi.fn();
const getProject = vi.fn();
const getProjects = vi.fn();
const updateValidationRepairSession = vi.fn();
const saveValidationRepairDraft = vi.fn();
const validateRepairSession = vi.fn();
const importRepairSession = vi.fn();
const downloadValidationSessionOriginal = vi.fn();
const downloadValidationSessionRepairDraft = vi.fn();
const suggestValidationRepairFixes = vi.fn();
const applyValidationRepairPatch = vi.fn();
const getValidationSessionContentLines = vi.fn();
const searchValidationSession = vi.fn();
const applyValidationSessionLinePatches = vi.fn();
const getValidationRepairHistory = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getProject: (...args: unknown[]) => getProject(...args),
    getProjects: (...args: unknown[]) => getProjects(...args),
    getValidationSession: (...args: unknown[]) => getValidationRepairSession(...args),
    getValidationSessionContent: (...args: unknown[]) => getValidationRepairContent(...args),
    updateValidationSession: (...args: unknown[]) => updateValidationRepairSession(...args),
    saveValidationSessionRepairDraft: (...args: unknown[]) => saveValidationRepairDraft(...args),
    validateValidationSession: (...args: unknown[]) => validateRepairSession(...args),
    importValidationSession: (...args: unknown[]) => importRepairSession(...args),
    downloadValidationSessionOriginal: (...args: unknown[]) => downloadValidationSessionOriginal(...args),
    downloadValidationSessionRepairDraft: (...args: unknown[]) => downloadValidationSessionRepairDraft(...args),
    suggestValidationSessionFixes: (...args: unknown[]) => suggestValidationRepairFixes(...args),
    applyValidationSessionPatch: (...args: unknown[]) => applyValidationRepairPatch(...args),
    getValidationSessionContentLines: (...args: unknown[]) => getValidationSessionContentLines(...args),
    searchValidationSession: (...args: unknown[]) => searchValidationSession(...args),
    applyValidationSessionLinePatches: (...args: unknown[]) => applyValidationSessionLinePatches(...args),
    getValidationSessionHistory: (...args: unknown[]) => getValidationRepairHistory(...args),
    getValidationRepairSession: (...args: unknown[]) => getValidationRepairSession(...args),
    getValidationRepairContent: (...args: unknown[]) => getValidationRepairContent(...args),
    updateValidationRepairSession: (...args: unknown[]) => updateValidationRepairSession(...args),
    saveValidationRepairDraft: (...args: unknown[]) => saveValidationRepairDraft(...args),
    validateRepairSession: (...args: unknown[]) => validateRepairSession(...args),
    importRepairSession: (...args: unknown[]) => importRepairSession(...args),
    suggestValidationRepairFixes: (...args: unknown[]) => suggestValidationRepairFixes(...args),
    applyValidationRepairPatch: (...args: unknown[]) => applyValidationRepairPatch(...args),
    getValidationRepairHistory: (...args: unknown[]) => getValidationRepairHistory(...args),
  };
});

import { ValidationRepairWorkspace } from '@/components/sboms/ValidationRepairWorkspace';

const FAILED_SESSION: ValidationRepairSession = {
  id: 'session-1',
  project_id: 42,
  user_id: null,
  original_filename: 'bad.json',
  sbom_name: 'bad',
  sbom_type: null,
  detected_format: 'cyclonedx',
  detected_version: '1.6',
  current_content: '{"bomFormat":"CycloneDX","components":[{"purl":"not-a-purl"}]}',
  content_inline_truncated: false,
  file_size_bytes: 61,
  sha256: 'abc',
  original_size_bytes: 61,
  original_sha256: 'abc',
  stored_size_bytes: 61,
  stored_sha256: 'abc',
  total_lines: 1,
  validation_status: 'failed',
  latest_error_report: {
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
        stage_number: 4,
        path: 'components[0].purl',
        message: 'Package URL is malformed.',
        remediation: 'Replace with a valid package URL.',
        spec_reference: null,
        can_ai_fix: true,
      },
    ],
  },
  can_edit: true,
  can_ai_fix: true,
  security_blocked_reason: null,
  created_at: '2026-06-12T00:00:00Z',
  updated_at: '2026-06-12T00:00:00Z',
  expires_at: '2026-06-19T00:00:00Z',
  imported_sbom_id: null,
};

const PASSED_SESSION: ValidationRepairSession = {
  ...FAILED_SESSION,
  validation_status: 'passed',
  current_content: '{"bomFormat":"CycloneDX","components":[{"purl":"pkg:generic/x@1.0.0"}]}',
  latest_error_report: {
    status: 'passed',
    failed_stage: null,
    error_count: 0,
    warning_count: 0,
    info_count: 0,
    truncated: false,
    entries: [],
  },
};

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  push.mockReset();
  getProject.mockReset();
  getProject.mockResolvedValue({
    id: 42,
    project_name: 'Payments',
    project_details: null,
    project_status: 1,
    created_by: null,
    created_on: null,
    modified_by: null,
    modified_on: null,
  });
  getProjects.mockReset();
  getProjects.mockResolvedValue([
    {
      id: 42,
      project_name: 'Payments',
      project_details: null,
      project_status: 1,
      created_by: null,
      created_on: null,
      modified_by: null,
      modified_on: null,
    }
  ]);
  getValidationRepairSession.mockResolvedValue(FAILED_SESSION);
  getValidationRepairContent.mockReset();
  getValidationRepairContent.mockResolvedValue({
    offset: 0,
    limit: 65536,
    total_size: FAILED_SESSION.current_content.length,
    content: FAILED_SESSION.current_content,
    eof: true,
    sha256: 'abc',
  });
  getValidationRepairHistory.mockResolvedValue([
    {
      id: 1,
      session_id: 'session-1',
      event_type: 'created',
      actor_user_id: null,
      timestamp: '2026-06-12T00:00:00Z',
      summary: 'created',
      before_hash: null,
      after_hash: 'abc',
      metadata: {},
    },
  ]);
  updateValidationRepairSession.mockResolvedValue(FAILED_SESSION);
  saveValidationRepairDraft.mockReset();
  saveValidationRepairDraft.mockResolvedValue(FAILED_SESSION);
  validateRepairSession.mockResolvedValue(FAILED_SESSION);
  downloadValidationSessionOriginal.mockReset();
  downloadValidationSessionOriginal.mockResolvedValue({ blob: new Blob(['original']), filename: 'bad.json' });
  downloadValidationSessionRepairDraft.mockReset();
  downloadValidationSessionRepairDraft.mockResolvedValue({ blob: new Blob(['draft']), filename: 'bad.repaired.json' });
  getValidationSessionContentLines.mockReset();
  getValidationSessionContentLines.mockResolvedValue({
    start_line: 1,
    line_count: 500,
    total_lines: 120000,
    lines: ['{', '"bomFormat":"CycloneDX"', '}'],
    eof: false,
  });
  searchValidationSession.mockReset();
  searchValidationSession.mockResolvedValue({
    query: '',
    source: 'repair_draft',
    limit: 100,
    matches: [],
    truncated: false,
  });
  applyValidationSessionLinePatches.mockReset();
  applyValidationSessionLinePatches.mockResolvedValue(FAILED_SESSION);
  suggestValidationRepairFixes.mockResolvedValue({
    summary: 'Fix malformed purl',
    risk: 'low',
    requires_user_review: true,
    patches: [
      {
        target: '/components/0/purl',
        operation: 'replace',
        before: 'not-a-purl',
        after: 'pkg:generic/x@1.0.0',
        reason: 'Use a valid purl.',
        validation_error_codes: ['SBOM_VAL_E052_PURL_INVALID'],
      },
    ],
  });
  applyValidationRepairPatch.mockResolvedValue(PASSED_SESSION);
  const imported: SBOMSource = {
    id: 101,
    sbom_name: 'bad',
    sbom_type: null,
    sbom_version: null,
    projectid: 42,
    project_id: 42,
    project_name: 'Payments',
    created_by: null,
    created_on: '2026-06-12T00:00:00Z',
    modified_by: null,
    modified_on: null,
    productver: null,
    status: 'validated',
  };
  importRepairSession.mockResolvedValue(imported);
});

describe('ValidationRepairWorkspace', () => {
  it('renders the editor and validation errors grouped by stage', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    expect(await screen.findByLabelText('SBOM repair editor')).toHaveValue(FAILED_SESSION.current_content);
    expect(getValidationRepairContent).toHaveBeenCalledWith('session-1', 0, 65536, expect.any(AbortSignal));
    expect(screen.getByText('session-1')).toBeInTheDocument();
    expect(screen.getByText('bad.json')).toBeInTheDocument();
    expect(await screen.findByText('Payments')).toBeInTheDocument();
    expect(screen.getByText('Stage 4 · Semantic Validation')).toBeInTheDocument();
    expect(screen.getByText('SBOM_VAL_E052_PURL_INVALID')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Import SBOM/i })).toBeDisabled();
    expect(screen.getByText('Repair History').closest('details')).not.toHaveAttribute('open');
    expect(screen.getByLabelText('SBOM repair editor')).toHaveClass('h-full', 'flex-1', 'min-h-0', 'overflow-auto');
  });

  it('collapses the validation panel and expands the editor controls', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    expect(await screen.findByText('Validation Status')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Hide validation panel/i }));

    expect(screen.queryByText('Validation Status')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Show validation panel/i })).toBeInTheDocument();
  });

  it('uses focus mode to hide summary and validation side panel', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    expect(await screen.findByText('Validation Session')).toBeInTheDocument();
    expect(screen.getByText('Validation Status')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Focus mode$/i }));

    expect(screen.queryByText('Validation Session')).not.toBeInTheDocument();
    expect(screen.queryByText('Validation Status')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Exit focus mode/i })).toBeInTheDocument();
  });

  it('renders large file mode with a full-height chunked viewer', async () => {
    getValidationRepairSession.mockResolvedValue({
      ...FAILED_SESSION,
      full_editor_allowed: false,
      is_large_file: true,
      file_size_bytes: 8_000_000,
      original_size_bytes: 8_000_000,
      total_lines: 120000,
    });

    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    expect(await screen.findByText('Large File Mode')).toBeInTheDocument();
    expect(getValidationSessionContentLines).toHaveBeenCalledWith('session-1', 1, 500, expect.any(AbortSignal));
    expect(screen.getByText('Lines 1-3').closest('div')).toHaveClass('bg-surface-muted');
    expect(screen.getByText('"bomFormat":"CycloneDX"')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Hide validation panel/i })).toBeInTheDocument();
    expect(screen.queryByLabelText('SBOM repair editor')).not.toBeInTheDocument();
  });

  it('saves before revalidating the current editor content', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const editor = await screen.findByLabelText('SBOM repair editor');
    fireEvent.change(editor, { target: { value: '{"changed":true}' } });

    fireEvent.click(screen.getByRole('button', { name: /Revalidate/i }));

    await waitFor(() => expect(saveValidationRepairDraft).toHaveBeenCalledWith('session-1', '{"changed":true}', FAILED_SESSION.updated_at));
    await waitFor(() => expect(validateRepairSession).toHaveBeenCalledWith('session-1'));
  });

  it('loads more content before enabling full-draft editing for partial chunks', async () => {
    getValidationRepairContent
      .mockResolvedValueOnce({
        offset: 0,
        limit: 65536,
        total_size: 12,
        content: 'first ',
        eof: false,
        sha256: 'chunked',
      })
      .mockResolvedValueOnce({
        offset: 6,
        limit: 65536,
        total_size: 12,
        content: 'second',
        eof: true,
        sha256: 'chunked',
      });

    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    const editor = await screen.findByLabelText('SBOM repair editor');
    expect(editor).toHaveValue('first ');
    expect(editor).toBeDisabled();
    expect(screen.getByText('Preview loaded')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Load more/i }));

    await waitFor(() => expect(getValidationRepairContent).toHaveBeenCalledWith('session-1', 6, 65536));
    expect(await screen.findByText('Full repair draft loaded')).toBeInTheDocument();
    expect(screen.getByLabelText('SBOM repair editor')).toHaveValue('first second');
  });

  it('shows AI diff suggestions and applies selected patches', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    fireEvent.click(await screen.findByRole('button', { name: /AI fix/i }));

    expect(await screen.findByText('Fix malformed purl')).toBeInTheDocument();
    expect(screen.getByText('not-a-purl')).toBeInTheDocument();
    expect(screen.getByText('pkg:generic/x@1.0.0')).toBeInTheDocument();
    expect(screen.getByLabelText('SBOM repair editor')).toHaveValue(FAILED_SESSION.current_content);

    fireEvent.click(screen.getByRole('button', { name: /Apply selected/i }));

    await waitFor(() => expect(applyValidationRepairPatch).toHaveBeenCalledWith(
      'session-1',
      expect.objectContaining({
        patches: expect.arrayContaining([expect.objectContaining({ target: '/components/0/purl' })]),
      }),
    ));
    expect(await screen.findByText(/Patch applied and validation passed/i)).toBeInTheDocument();
  });

  it('enables import after validation passes and navigates to the imported SBOM', async () => {
    getValidationRepairSession.mockResolvedValue(PASSED_SESSION);
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    const importButton = await screen.findByRole('button', { name: /Import SBOM/i });
    expect(importButton).toBeEnabled();
    fireEvent.click(importButton);

    await waitFor(() => expect(importRepairSession).toHaveBeenCalledWith('session-1', true));
    await waitFor(() => expect(push).toHaveBeenCalledWith('/sboms/101'));
  });

  it('renders a non-editable security-blocked state', async () => {
    getValidationRepairSession.mockResolvedValue({
      ...FAILED_SESSION,
      validation_status: 'security_blocked',
      can_edit: false,
      can_ai_fix: false,
      security_blocked_reason: 'Payload blocked by security validation',
    });

    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    expect(await screen.findByText('Security-blocked payload')).toBeInTheDocument();
    expect(screen.getByText('Payload blocked by security validation')).toBeInTheDocument();
  });

  it('renders a user-friendly API error state for failed actions and history loading', async () => {
    getValidationRepairHistory.mockRejectedValue(new Error('history unavailable'));
    saveValidationRepairDraft.mockRejectedValue(new Error('save failed'));

    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const editor = await screen.findByLabelText('SBOM repair editor');
    fireEvent.change(editor, { target: { value: '{"changed":true}' } });
    fireEvent.click(screen.getByRole('button', { name: /Save changes/i }));

    expect(await screen.findByText('Could not load repair history')).toBeInTheDocument();
    expect(await screen.findByText('Repair action failed')).toBeInTheDocument();
    expect(screen.getByText('save failed')).toBeInTheDocument();
  });
});
