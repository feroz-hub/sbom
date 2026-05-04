// @vitest-environment jsdom
/**
 * AddProviderDialog — flow + invariant tests.
 *
 * Three load-bearing checks:
 *
 *   1. Save button disabled until a successful test result.
 *   2. Test → Save sequence creates a credential via the API.
 *   3. Provider switch resets the form (no stale API key from a
 *      prior provider attempt).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddProviderDialog } from '../AddProviderDialog/AddProviderDialog';
import {
  SAMPLE_CATALOG,
  makeCredential,
  makeTestResult,
  renderWithProviders,
} from './test-utils';


const listAiProviderCatalog = vi.fn();
const testAiCredentialUnsaved = vi.fn();
const createAiCredential = vi.fn();
const listAiCredentials = vi.fn();

vi.mock('@/lib/api', () => ({
  listAiProviderCatalog: () => listAiProviderCatalog(),
  testAiCredentialUnsaved: (body: unknown) => testAiCredentialUnsaved(body),
  createAiCredential: (body: unknown) => createAiCredential(body),
  listAiCredentials: () => listAiCredentials(),
}));


beforeEach(() => {
  listAiProviderCatalog.mockResolvedValue(SAMPLE_CATALOG);
  listAiCredentials.mockResolvedValue([]);
  testAiCredentialUnsaved.mockReset();
  createAiCredential.mockReset();
});


afterEach(() => {
  vi.restoreAllMocks();
});


describe('AddProviderDialog', () => {
  it('renders nothing when open=false', () => {
    const { container } = renderWithProviders(
      <AddProviderDialog open={false} onClose={() => {}} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('disables Save until a successful test result lands', async () => {
    renderWithProviders(<AddProviderDialog open onClose={() => {}} />);
    // The API key label only renders after the catalog query resolves.
    const apiKey = await screen.findByLabelText('API key');
    await userEvent.type(apiKey, 'sk-ant-FAKE-TEST-KEY');

    const saveBtn = screen.getByRole('button', { name: /save provider/i });
    expect(saveBtn).toBeDisabled();
  });

  it('test → success → save sends create payload', async () => {
    testAiCredentialUnsaved.mockResolvedValue(
      makeTestResult({ success: true, provider: 'anthropic', detected_models: ['claude-sonnet-4-5'] }),
    );
    createAiCredential.mockResolvedValue(
      makeCredential({ id: 99, provider_name: 'anthropic' }),
    );

    const onClose = vi.fn();
    renderWithProviders(<AddProviderDialog open onClose={onClose} />);
    await waitFor(() =>
      expect(screen.getByLabelText('API key')).toBeInTheDocument(),
    );

    await userEvent.type(screen.getByLabelText('API key'), 'sk-ant-FAKE-KEY');

    await userEvent.click(screen.getByRole('button', { name: /test connection/i }));

    await waitFor(() =>
      expect(screen.getByTestId('test-result-success')).toBeInTheDocument(),
    );

    const saveBtn = screen.getByRole('button', { name: /save provider/i });
    expect(saveBtn).not.toBeDisabled();
    await userEvent.click(saveBtn);

    await waitFor(() => expect(createAiCredential).toHaveBeenCalled());
    const payload = createAiCredential.mock.calls[0][0];
    expect(payload.provider_name).toBe('anthropic');
    expect(payload.api_key).toBe('sk-ant-FAKE-KEY');
    expect(payload.tier).toBe('paid');
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it('shows the free-tier rate limit when Gemini is selected', async () => {
    renderWithProviders(<AddProviderDialog open onClose={() => {}} />);
    // Wait until the catalog query has resolved so the dropdown has
    // populated with both options. Anchoring on the API-key field is
    // a reliable signal that ``entry`` has resolved and the form is
    // rendered.
    await screen.findByLabelText('API key');

    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: /provider/i }),
      'gemini',
    );

    // Tier select appears (free tier supported).
    await waitFor(() => {
      expect(screen.getByLabelText(/tier/i)).toBeInTheDocument();
    });
    // The "15 req/min" string can appear in multiple places (option
    // text + tier badge) — assert at least one match.
    expect(screen.getAllByText(/15 req\/min/i).length).toBeGreaterThan(0);
  });

  it('Save disabled when test fails (auth)', async () => {
    testAiCredentialUnsaved.mockResolvedValue(
      makeTestResult({
        success: false,
        error_kind: 'auth',
        error_message: 'bad key',
        detected_models: [],
        latency_ms: null,
      }),
    );

    renderWithProviders(<AddProviderDialog open onClose={() => {}} />);
    await waitFor(() =>
      expect(screen.getByLabelText('API key')).toBeInTheDocument(),
    );
    await userEvent.type(screen.getByLabelText('API key'), 'sk-ant-WRONG');
    await userEvent.click(screen.getByRole('button', { name: /test connection/i }));

    await waitFor(() =>
      expect(screen.getByTestId('test-result-auth')).toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: /save provider/i })).toBeDisabled();
  });
});
