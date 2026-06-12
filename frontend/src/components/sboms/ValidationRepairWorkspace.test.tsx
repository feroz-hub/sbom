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
const updateValidationRepairSession = vi.fn();
const validateRepairSession = vi.fn();
const importRepairSession = vi.fn();
const suggestValidationRepairFixes = vi.fn();
const applyValidationRepairPatch = vi.fn();
const getValidationRepairHistory = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getValidationRepairSession: (...args: unknown[]) => getValidationRepairSession(...args),
    updateValidationRepairSession: (...args: unknown[]) => updateValidationRepairSession(...args),
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
  project_id: null,
  user_id: null,
  original_filename: 'bad.json',
  sbom_name: 'bad',
  sbom_type: null,
  detected_format: 'cyclonedx',
  detected_version: '1.6',
  current_content: '{"bomFormat":"CycloneDX","components":[{"purl":"not-a-purl"}]}',
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
  getValidationRepairSession.mockResolvedValue(FAILED_SESSION);
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
  validateRepairSession.mockResolvedValue(FAILED_SESSION);
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
    projectid: null,
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
    expect(screen.getByText('Stage 4 · Semantic')).toBeInTheDocument();
    expect(screen.getByText('SBOM_VAL_E052_PURL_INVALID')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Import SBOM/i })).toBeDisabled();
  });

  it('saves before revalidating the current editor content', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));
    const editor = await screen.findByLabelText('SBOM repair editor');
    fireEvent.change(editor, { target: { value: '{"changed":true}' } });

    fireEvent.click(screen.getByRole('button', { name: /Revalidate/i }));

    await waitFor(() => expect(updateValidationRepairSession).toHaveBeenCalledWith('session-1', '{"changed":true}'));
    await waitFor(() => expect(validateRepairSession).toHaveBeenCalledWith('session-1'));
  });

  it('shows AI diff suggestions and applies selected patches', async () => {
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    fireEvent.click(await screen.findByRole('button', { name: /AI fix/i }));

    expect(await screen.findByText('Fix malformed purl')).toBeInTheDocument();
    expect(screen.getByText('not-a-purl')).toBeInTheDocument();
    expect(screen.getByText('pkg:generic/x@1.0.0')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Apply selected/i }));

    await waitFor(() => expect(applyValidationRepairPatch).toHaveBeenCalledWith(
      'session-1',
      expect.arrayContaining([expect.objectContaining({ target: '/components/0/purl' })]),
    ));
    expect(await screen.findByText(/Patch applied and validation passed/i)).toBeInTheDocument();
  });

  it('enables import after validation passes and navigates to the imported SBOM', async () => {
    getValidationRepairSession.mockResolvedValue(PASSED_SESSION);
    render(wrap(<ValidationRepairWorkspace sessionId="session-1" />));

    const importButton = await screen.findByRole('button', { name: /Import SBOM/i });
    expect(importButton).toBeEnabled();
    fireEvent.click(importButton);

    await waitFor(() => expect(importRepairSession).toHaveBeenCalledWith('session-1'));
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
});
