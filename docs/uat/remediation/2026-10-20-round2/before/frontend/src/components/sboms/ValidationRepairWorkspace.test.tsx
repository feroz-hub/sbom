// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
const repairAnalysisMock = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    analyzeSbomRepair: (...args: unknown[]) => repairAnalysisMock(...args),
    getLatestSbomRepair: vi.fn().mockResolvedValue(null),
    getSessionQuality: vi.fn().mockResolvedValue({ enabled: false, assessment: null }),
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

afterEach(() => vi.unstubAllGlobals());
beforeEach(() => {
  vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { callback(0); return 1; });
  repairAnalysisMock.mockReset().mockResolvedValue({ enabled: false });
  getValidationRepairSession.mockReset();
  validateRepairSession.mockReset();
  importRepairSession.mockReset();
  suggestValidationRepairFixes.mockReset();
  applyValidationRepairPatch.mockReset();
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
  it('keeps original and report downloads available in editor utilities', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:test');
    vi.stubGlobal('URL', class extends URL { static createObjectURL = createObjectURL; static revokeObjectURL = vi.fn(); });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    try {
      render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
      await screen.findByLabelText('SBOM repair editor');
      fireEvent.click(screen.getByLabelText('Editor utilities'));
      fireEvent.click(screen.getByRole('button', { name: 'Download original' }));
      await waitFor(() => expect(downloadValidationSessionOriginal).toHaveBeenCalledWith('session-1'));
      await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole('button', { name: 'Download validation report' }));
      expect(createObjectURL).toHaveBeenCalledTimes(2);
      expect(click).toHaveBeenCalledTimes(2);
    } finally { click.mockRestore(); }
  });
  it('supports arrow navigation between mobile tabs', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    await screen.findByLabelText('SBOM repair editor');
    const issues = screen.getByRole('tab', { name: /Issues/ });
    fireEvent.keyDown(issues, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: 'Editor' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: 'Editor' })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Editor' }), { key: 'Home' });
    expect(issues).toHaveAttribute('aria-selected', 'true');
  });
  it('renders structured issues and keeps secondary metadata collapsed', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    // The editor mounts before the separate content request has populated it.
    await waitFor(() => expect(screen.getByLabelText('SBOM repair editor')).toHaveValue(FAILED_SESSION.current_content));
    expect(getValidationRepairContent).toHaveBeenCalledWith('session-1', 0, 65536, expect.any(AbortSignal));
    expect(screen.getByText('session-1')).toBeInTheDocument();
    expect(screen.getByText('bad.json')).toBeInTheDocument();
    expect(await screen.findByRole('option', { name: 'Payments' })).toBeInTheDocument();
    expect(screen.getByRole('article', { name: 'E052 Invalid package URL' })).toBeInTheDocument();
    expect(screen.getByText('SBOM Information').closest('details')).not.toHaveAttribute('open');
    expect(screen.getAllByText('SBOM_VAL_E052_PURL_INVALID').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /^Import SBOM$/i })).toBeDisabled();
    expect(screen.getByText('Repair History').closest('details')).not.toHaveAttribute('open');
    expect(screen.getByLabelText('SBOM repair editor')).toHaveClass('h-full', 'flex-1', 'min-h-0', 'overflow-auto');
  });

  it('provides mobile issue/editor navigation without a blocking wizard', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    await screen.findByRole('region', { name: 'Validation Issues' });
    fireEvent.click(screen.getByRole('tab', { name: 'Editor' }));
    expect(screen.getByRole('tab', { name: 'Editor' })).toHaveAttribute('aria-selected', 'true');
    expect(document.getElementById('repair-issues-pane')).toHaveClass('hidden');
    fireEvent.click(screen.getByRole('tab', { name: 'Issues (1)' }));
    expect(screen.getByRole('tab', { name: 'Issues (1)' })).toHaveAttribute('aria-selected', 'true');
  });

  it('keeps issues and revalidation available in focus mode', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    await screen.findByText('SBOM Information');
    fireEvent.click(screen.getByLabelText('Editor utilities'));
    fireEvent.click(screen.getByRole('button', { name: /^Focus mode$/i }));
    expect(screen.queryByText('SBOM Information')).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Validation Issues' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Revalidate$/i })).toBeEnabled();
    expect(screen.getAllByRole('button', { name: /Exit focus mode/i }).length).toBeGreaterThan(0);
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
    expect(screen.getByRole('region', { name: 'Validation Issues' })).toBeInTheDocument();
    expect(screen.queryByLabelText('SBOM repair editor')).not.toBeInTheDocument();
  });

  it('saves before revalidating the current editor content', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const editor = await screen.findByLabelText('SBOM repair editor');
    fireEvent.change(editor, { target: { value: '{"changed":true}' } });

    fireEvent.click(screen.getByRole('button', { name: /^Revalidate$/i }));

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
    expect(screen.getByText(/Preview loaded/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Load more/i }));

    await waitFor(() => expect(getValidationRepairContent).toHaveBeenCalledWith('session-1', 6, 65536));
    await waitFor(() => expect(screen.getByLabelText('SBOM repair editor')).toHaveValue('first second'));
    expect(screen.getByLabelText('SBOM repair editor')).toBeEnabled();
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

    const importButton = await screen.findByRole('button', { name: /^Import SBOM$/i });
    await waitFor(() => expect(importButton).toBeEnabled());
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
    fireEvent.click(screen.getByRole('button', { name: /^Save draft$/i }));

    expect(await screen.findByText('Could not load repair history')).toBeInTheDocument();
    expect(await screen.findByText('Repair action failed')).toBeInTheDocument();
    expect(screen.getByText('save failed')).toBeInTheDocument();
  });
});


describe('Repair Workspace workflow', () => {
  it('navigates to the exact JSON value and preserves issue selection while editing', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    await screen.findByRole('article', { name: 'E052 Invalid package URL' });
    fireEvent.click(screen.getByRole('button', { name: 'Go to location →' }));
    const editor = screen.getByLabelText('SBOM repair editor') as HTMLTextAreaElement;
    expect(editor.value.slice(editor.selectionStart, editor.selectionEnd)).toBe('"not-a-purl"');
    expect(document.querySelector('[data-highlighted-line="1"]')).toBeInTheDocument();
    fireEvent.change(editor, { target: { value: editor.value.replace('not-a-purl', 'pkg:generic/x@1.0.0') } });
    expect(within(screen.getByLabelText('Issue list')).getByRole('button', { pressed: true })).toHaveTextContent('Invalid package URL');
    expect(screen.getByRole('button', { name: /^Import SBOM$/ })).toBeDisabled();
  });
  it('filters and searches issues using existing severities and classifications', async () => {
    const warning = { ...FAILED_SESSION.latest_error_report.entries[0], code: 'SBOM_VAL_W001_WARNING', severity: 'warning' as const, path: 'metadata.name', message: 'Name warning' };
    getValidationRepairSession.mockResolvedValue({ ...FAILED_SESSION, latest_error_report: { ...FAILED_SESSION.latest_error_report, warning_count: 1, entries: [...FAILED_SESSION.latest_error_report.entries, warning] } });
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const panel = await screen.findByRole('region', { name: 'Validation Issues' });
    fireEvent.click(within(panel).getByRole('button', { name: 'Warnings 1' }));
    expect(within(panel).queryByRole('article', { name: 'E052 Invalid package URL' })).not.toBeInTheDocument();
    expect(within(panel).getAllByRole('article')).toHaveLength(1);
    fireEvent.change(within(panel).getByLabelText('Search validation issues'), { target: { value: 'no-match' } });
    expect(within(panel).getByText('No issues match this filter.')).toBeInTheDocument();
    expect(within(panel).queryByRole('button', { name: 'Auto-fixable 0' })).not.toBeInTheDocument();
  });
  it('labels explicit manual-only issues without offering a safe fix', async () => {
    repairAnalysisMock.mockResolvedValue({ enabled: true, auto_fixable: 0, issues: [{ code: 'SBOM_VAL_E052_PURL_INVALID', path: 'components[0].purl', classification: 'MANUAL_ONLY' }] });
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    expect(await screen.findByText('MANUAL REVIEW')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Review safe repair' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Review automatic repairs/ })).not.toBeInTheDocument();
    expect(screen.getByText('This issue cannot be safely repaired automatically.')).toBeInTheDocument();
  });
  it('offers copy path when a location cannot be mapped without inventing a line', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    getValidationRepairSession.mockResolvedValue({ ...FAILED_SESSION, latest_error_report: { ...FAILED_SESSION.latest_error_report, entries: [{ ...FAILED_SESSION.latest_error_report.entries[0], path: 'missing.location' }] } });
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    fireEvent.click(await screen.findByRole('button', { name: 'Copy path' }));
    expect(writeText).toHaveBeenCalledWith('missing.location');
    expect(screen.queryByRole('button', { name: 'Go to location →' })).not.toBeInTheDocument();
    expect(document.querySelector('[data-highlighted-line]')).not.toBeInTheDocument();
  });
  it('refreshes issues after revalidation and enables import only for the saved validated draft', async () => {
    validateRepairSession.mockResolvedValue(PASSED_SESSION);
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const editor = await screen.findByLabelText('SBOM repair editor');
    fireEvent.change(editor, { target: { value: PASSED_SESSION.current_content } });
    fireEvent.click(screen.getByRole('button', { name: /^Revalidate$/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: /^Import SBOM$/ })).toBeEnabled());
    expect(screen.getByText('Passed')).toBeInTheDocument();
    expect(screen.queryByRole('article', { name: 'E052 Invalid package URL' })).not.toBeInTheDocument();
    fireEvent.change(editor, { target: { value: PASSED_SESSION.current_content + ' ' } });
    expect(screen.getByRole('button', { name: /^Import SBOM$/ })).toBeDisabled();
    expect(screen.getAllByText('The draft has changed. Revalidate it successfully before importing.').length).toBeGreaterThan(0);
  });
  it('does not mislabel a loaded Unicode draft as unsaved because byte counts differ', async () => {
    const content = '{"name":"Infusión 😀"}';
    getValidationRepairSession.mockResolvedValue({ ...PASSED_SESSION, current_content: content, stored_size_bytes: new TextEncoder().encode(content).length });
    getValidationRepairContent.mockResolvedValue({ offset: 0, limit: 65536, total_size: content.length, content, eof: true, sha256: 'abc' });
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    await waitFor(() => expect(screen.getByLabelText('SBOM repair editor')).toHaveValue(content));
    expect(screen.getByLabelText('SBOM repair editor')).toBeEnabled();
    expect(screen.getByRole('button', { name: /^Import SBOM$/ })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeDisabled();
  });
  it('keeps project assignment at import preparation and uses the existing update API', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const select = await screen.findByLabelText('Assign Project');
    expect(select).toHaveValue('42');
    fireEvent.change(select, { target: { value: '' } });
    await waitFor(() => expect(updateValidationRepairSession).toHaveBeenCalledWith('session-1', { project_id: null }));
    expect(screen.getByText('Destination project')).toBeInTheDocument();
  });
  it('uses reported lines in large-file mode and revalidates without saving an empty textarea', async () => {
    getValidationRepairSession.mockResolvedValue({ ...FAILED_SESSION, full_editor_allowed: false, total_lines: 120000, latest_error_report: { ...FAILED_SESSION.latest_error_report, entries: [{ ...FAILED_SESSION.latest_error_report.entries[0], line: 37 }] } });
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    fireEvent.click(await screen.findByRole('button', { name: 'Go to location →' }));
    await waitFor(() => expect(getValidationSessionContentLines).toHaveBeenCalledWith('session-1', 37, 500, expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole('button', { name: /^Revalidate$/ }));
    await waitFor(() => expect(validateRepairSession).toHaveBeenCalledWith('session-1'));
    expect(saveValidationRepairDraft).not.toHaveBeenCalled();
  });
  it('disables both revalidate controls while a validation request is pending', async () => {
    let complete!: (value: ValidationRepairSession) => void;
    validateRepairSession.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    fireEvent.click(await screen.findByRole('button', { name: /^Revalidate$/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revalidate SBOM from header' })).toBeDisabled());
    fireEvent.click(screen.getByRole('button', { name: 'Revalidate SBOM from header' }));
    expect(validateRepairSession).toHaveBeenCalledTimes(1);
    complete(FAILED_SESSION);
    await waitFor(() => expect(screen.getByRole('button', { name: /^Revalidate$/ })).toBeEnabled());
  });
});


it('hides and restores the mounted navigator without losing investigation state or edits', async () => {
  render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
  const editor = await screen.findByLabelText('SBOM repair editor') as HTMLTextAreaElement;
  const panel = screen.getByRole('region', { name: 'Validation Issues' });
  const search = within(panel).getByLabelText('Search validation issues');
  fireEvent.change(search, { target: { value: 'PURL' } });
  fireEvent.click(within(panel).getByRole('button', { name: 'Errors 1' }));
  fireEvent.click(within(panel).getByRole('button', { name: 'Go to location →' }));
  const selectedStart = editor.selectionStart;
  const list = screen.getByLabelText('Issue list'); list.scrollTop = 73;
  fireEvent.change(editor, { target: { value: editor.value + ' ' } });
  editor.setSelectionRange(selectedStart, selectedStart + 2);
  fireEvent.click(within(panel).getByRole('button', { name: 'Hide validation issues' }));
  expect(document.getElementById('repair-issues-pane')).toHaveClass('hidden');
  expect(document.querySelector('[data-issues-hidden="true"]')).toHaveClass('grid-cols-1');
  expect(screen.getByRole('button', { name: 'Show validation issues' })).toHaveFocus();
  expect(screen.getByLabelText('SBOM repair editor')).toBe(editor);
  expect(screen.getByRole('button', { name: 'Save draft' })).toBeEnabled();
  const draft = editor.value;
  fireEvent.click(screen.getByRole('button', { name: 'Show validation issues' }));
  expect(screen.getByLabelText('SBOM repair editor')).toBe(editor);
  expect(editor.value).toBe(draft);
  expect(editor.selectionStart).toBe(selectedStart);
  expect(search).toHaveValue('PURL');
  expect(within(panel).getByRole('button', { name: 'Errors 1' })).toHaveAttribute('aria-pressed', 'true');
  expect(list.scrollTop).toBe(73);
  expect(within(list).getByRole('button', { pressed: true })).toHaveTextContent('Invalid package URL');
  expect(document.getElementById('repair-issues-pane')).toHaveFocus();
  expect(saveValidationRepairDraft).not.toHaveBeenCalled();
  expect(validateRepairSession).not.toHaveBeenCalled();
});

vi.mock('@/hooks/useAuth', async () => ({ useAuth: (await import('@/test/authorizedAuth')).authorizedAuth }));
