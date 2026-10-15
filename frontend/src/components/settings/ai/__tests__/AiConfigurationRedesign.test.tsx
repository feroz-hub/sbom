// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { ConfigurationSummary } from '../ConfigurationSummary';
import { AiSettingsPage } from '../AiSettingsPage';
import { AiConfigurationScope } from '../ConfigurationScope';
import {
  SAMPLE_CATALOG,
  SAMPLE_SETTINGS,
  makeCredential,
  makeTestResult,
  renderWithProviders,
} from './test-utils';
import type { AiProviderModel } from '@/types/ai';

const api = vi.hoisted(() => ({
  listAiCredentials: vi.fn(),
  listAiProviderCatalog: vi.fn(),
  getAiCredentialSettings: vi.fn(),
  listAiProviderModels: vi.fn(),
  refreshAiProviderModels: vi.fn(),
  selectAiProviderModel: vi.fn(),
  testAiProviderModel: vi.fn(),
  testAiCredentialSaved: vi.fn(),
  setAiCredentialDefault: vi.fn(),
  setAiCredentialFallback: vi.fn(),
  updateAiCredential: vi.fn(),
  deleteAiCredential: vi.fn(),
}));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/usePermission', () => ({ usePermission: () => true }));
const model: AiProviderModel = {
  id: 7,
  provider_credential_id: 1,
  provider_name: 'anthropic',
  provider_model_id: 'models/EXACT-Id',
  runtime_model_id: 'EXACT-Id',
  display_name: 'Example model',
  is_available: true,
  is_enabled: true,
  is_selected: false,
  supports_chat: true,
  supports_streaming: null,
  supports_structured_output: false,
  supports_tools: null,
  context_window: 262144,
  max_output_tokens: 8192,
  discovery_source: 'live',
  first_discovered_at: null,
  last_discovered_at: '2026-10-15T12:00:00Z',
  last_verified_at: null,
  last_test_success: null,
  last_test_error: null,
};
const effective = {
  source: 'PLATFORM_DEFAULT' as const,
  override_enabled: false,
  feature_enabled: true,
  default_selection_key: 'saved:1',
  configured_providers: [
    {
      provider_name: 'anthropic',
      model: 'claude-sonnet-4-5',
      enabled: true,
      credential_present: true,
      is_default: true,
      selection_key: 'saved:1',
    },
  ],
};
function mount(canUpdate = true, canTest = true) {
  return renderWithProviders(
    <AiConfigurationScope.Provider
      value={{ scope: 'platform', key: 'platform', canUpdate, canTest }}
    >
      <AiSettingsPage effective={effective} />
    </AiConfigurationScope.Provider>,
  );
}
async function openModels() {
  await userEvent.click(screen.getByRole('tab', { name: 'Models' }));
  await screen.findByText('EXACT-Id');
}
beforeEach(() => {
  vi.resetAllMocks();
  api.listAiCredentials.mockResolvedValue([
    makeCredential(),
    makeCredential({
      id: 2,
      provider_name: 'ollama',
      label: 'Local',
      api_key_present: false,
      is_default: false,
      last_test_at: null,
      last_test_success: null,
    }),
  ]);
  api.listAiProviderCatalog.mockResolvedValue(SAMPLE_CATALOG);
  api.getAiCredentialSettings.mockResolvedValue(SAMPLE_SETTINGS);
  api.listAiProviderModels.mockImplementation((id) =>
    Promise.resolve(id === 1 ? [model] : []),
  );
  api.refreshAiProviderModels.mockResolvedValue({
    discovered: 1,
    created: 0,
    updated: 1,
    unavailable: 0,
  });
  api.selectAiProviderModel.mockResolvedValue({ ...model, is_selected: true });
  api.testAiProviderModel.mockResolvedValue({ success: true });
  api.testAiCredentialSaved.mockResolvedValue(makeTestResult());
  api.setAiCredentialDefault.mockResolvedValue(makeCredential());
  api.setAiCredentialFallback.mockResolvedValue(
    makeCredential({ is_fallback: true }),
  );
  api.updateAiCredential.mockResolvedValue(makeCredential({ enabled: false }));
  api.deleteAiCredential.mockResolvedValue(undefined);
});

describe('AI configuration redesign', () => {
  it('shows the effective default and model separately from credentials and connection status', async () => {
    mount();
    const summary = screen.getByRole('region', {
      name: 'Effective configuration',
    });
    expect(
      await within(summary).findByText('Anthropic Claude'),
    ).toBeInTheDocument();
    expect(within(summary).getByText('claude-sonnet-4-5')).toBeInTheDocument();
    const ollama = await screen.findByTestId('ai-provider-card-2');
    expect(
      within(ollama).getByText(
        'Credentials: Not configured (may not be required)',
      ),
    ).toBeInTheDocument();
    expect(within(ollama).getByText('Not tested')).toBeInTheDocument();
    expect(api.listAiCredentials).toHaveBeenCalledWith(
      expect.any(AbortSignal),
      'platform',
    );
    expect(api.listAiProviderModels).not.toHaveBeenCalled();
  });
  it('searches providers and opens provider-scoped models', async () => {
    mount();
    await screen.findByTestId('ai-provider-card-1');
    await userEvent.type(
      screen.getByRole('searchbox', { name: 'Search providers' }),
      'Local',
    );
    expect(screen.queryByTestId('ai-provider-card-1')).not.toBeInTheDocument();
    await userEvent.click(
      screen.getByRole('button', { name: 'Manage models' }),
    );
    expect(screen.getByRole('combobox', { name: 'Provider' })).toHaveValue('2');
    expect(
      await screen.findByText(/No models discovered yet/),
    ).toBeInTheDocument();
    expect(api.listAiProviderModels).toHaveBeenCalledWith(
      2,
      expect.any(AbortSignal),
      'platform',
    );
  });
  it('searches exact provider model IDs and retains complete metadata in details', async () => {
    mount();
    await openModels();
    await userEvent.type(
      screen.getByRole('searchbox', { name: 'Search models' }),
      'models/exact',
    );
    await userEvent.click(screen.getByText('Capabilities and details'));
    expect(screen.getByText('262,144')).toBeInTheDocument();
    expect(screen.getByText('8,192')).toBeInTheDocument();
    expect(screen.getByText('stream: unknown')).toBeInTheDocument();
    expect(
      screen.getByText('Provider ID: models/EXACT-Id'),
    ).toBeInTheDocument();
    await userEvent.type(
      screen.getByRole('searchbox', { name: 'Search models' }),
      '-missing',
    );
    expect(
      screen.getByText('No models match your search.'),
    ).toBeInTheDocument();
  });
  it('retains rows after a failed refresh and keeps refresh scoped', async () => {
    api.refreshAiProviderModels.mockRejectedValue(
      new Error('Discovery unavailable'),
    );
    mount();
    await openModels();
    await userEvent.click(
      screen.getAllByRole('button', { name: 'Refresh models' })[0],
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Discovery unavailable',
    );
    expect(screen.getByText('EXACT-Id')).toBeInTheDocument();
    expect(api.refreshAiProviderModels).toHaveBeenCalledWith(
      1,
      undefined,
      'platform',
    );
    expect(api.selectAiProviderModel).not.toHaveBeenCalled();
  });
  it('does not activate until confirmed and preserves the old state on failure', async () => {
    api.selectAiProviderModel.mockRejectedValue(new Error('Model unavailable'));
    mount();
    await openModels();
    await userEvent.click(screen.getByRole('button', { name: 'Set active' }));
    expect(api.selectAiProviderModel).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toHaveTextContent(
      'tenants that inherit',
    );
    await userEvent.click(
      screen.getByRole('button', { name: 'Confirm activation' }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Model unavailable',
    );
    expect(screen.getByText('Inactive')).toBeInTheDocument();
    expect(api.selectAiProviderModel).toHaveBeenCalledWith(
      1,
      7,
      undefined,
      'platform',
    );
  });
  it('updates activation only after the authoritative read and disables the active action', async () => {
    api.selectAiProviderModel.mockImplementation(async () => {
      api.listAiProviderModels.mockImplementation((id) =>
        Promise.resolve(id === 1 ? [{ ...model, is_selected: true }] : []),
      );
      return { ...model, is_selected: true };
    });
    mount();
    await openModels();
    await userEvent.click(screen.getByRole('button', { name: 'Set active' }));
    await userEvent.click(
      screen.getByRole('button', { name: 'Confirm activation' }),
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Active' })).toBeDisabled(),
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('shows model test request errors with the model identity', async () => {
    api.testAiProviderModel.mockRejectedValue(new Error('Timed out'));
    mount();
    await openModels();
    await userEvent.click(screen.getByRole('button', { name: 'Test' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'EXACT-Id: Timed out',
    );
    expect(api.testAiProviderModel).toHaveBeenCalledWith(
      1,
      7,
      undefined,
      'platform',
    );
  });
  it('prevents duplicate connection tests while running', async () => {
    api.testAiCredentialSaved.mockReturnValue(new Promise(() => {}));
    mount();
    const button = await screen.findByRole('button', {
      name: 'Test connection for Anthropic Claude',
    });
    await userEvent.dblClick(button);
    expect(button).toBeDisabled();
    expect(api.testAiCredentialSaved).toHaveBeenCalledTimes(1);
  });
  it('keeps fallback, enable and confirmed deletion actions reachable', async () => {
    mount();
    const more = await screen.findByRole('button', {
      name: 'More actions for ollama',
    });
    await userEvent.click(more);
    await userEvent.click(
      screen.getByRole('button', { name: 'Set as fallback' }),
    );
    await waitFor(() =>
      expect(api.setAiCredentialFallback).toHaveBeenCalledWith(
        2,
        undefined,
        'platform',
      ),
    );
    await userEvent.click(more);
    await userEvent.click(screen.getByRole('button', { name: 'Disable' }));
    await waitFor(() =>
      expect(api.updateAiCredential).toHaveBeenCalledWith(
        2,
        { enabled: false },
        undefined,
        'platform',
      ),
    );
    await userEvent.click(more);
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    const remove = screen.getByRole('button', { name: 'Delete credential' });
    expect(remove).toBeDisabled();
    await userEvent.type(
      screen.getByRole('textbox', { name: 'Confirm provider name' }),
      'ollama',
    );
    await userEvent.click(remove);
    await waitFor(() =>
      expect(api.deleteAiCredential).toHaveBeenCalledWith(
        2,
        undefined,
        'platform',
      ),
    );
  });
  it('confirms the impact before changing the default provider', async () => {
    mount();
    await userEvent.click(
      await screen.findByRole('button', { name: 'More actions for ollama' }),
    );
    await userEvent.click(
      screen.getByRole('button', { name: 'Set as default' }),
    );
    expect(api.setAiCredentialDefault).not.toHaveBeenCalled();
    await userEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Set as default',
      }),
    );
    await waitFor(() =>
      expect(api.setAiCredentialDefault).toHaveBeenCalledWith(
        2,
        undefined,
        'platform',
      ),
    );
  });
  it('provides safe details with update and test actions disabled for read-only access', async () => {
    mount(false, false);
    await screen.findByTestId('ai-provider-card-1');
    expect(
      screen.queryByRole('button', { name: 'Add provider' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Edit' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', {
        name: 'Test connection for Anthropic Claude',
      }),
    ).toBeDisabled();
    await openModels();
    expect(
      screen.queryByRole('button', { name: 'Set active' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(
      screen.getAllByRole('button', { name: 'Refresh models' })[0],
    ).toBeDisabled();
  });
  it('supports keyboard tabs and preserves budget controls under defaults', async () => {
    mount();
    const providers = screen.getByRole('tab', { name: 'Providers' });
    providers.focus();
    await userEvent.keyboard('{End}');
    expect(
      screen.getByRole('tab', { name: 'Defaults & Overrides' }),
    ).toHaveFocus();
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Budget caps');
    await userEvent.keyboard('{Home}{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Models' })).toHaveFocus();
  });
  it('has no axe violations in each view', async () => {
    const { container } = mount();
    await screen.findByTestId('ai-provider-card-1');
    expect((await axe(container)).violations).toEqual([]);
    await openModels();
    expect((await axe(container)).violations).toEqual([]);
    await userEvent.click(
      screen.getByRole('tab', { name: 'Defaults & Overrides' }),
    );
    expect((await axe(container)).violations).toEqual([]);
  });
});

describe('effective configuration source of truth', () => {
  it('shows an environment-backed default even when a different saved provider exists', async () => {
    renderWithProviders(
      <ConfigurationSummary
        effective={{
          ...effective,
          default_selection_key: 'env:ollama',
          configured_providers: [
            {
              provider_name: 'ollama',
              model: 'Exact-Env-Model',
              enabled: true,
              credential_present: false,
              selection_key: 'env:ollama',
            },
          ],
        }}
        onDetails={() => {}}
      />,
    );
    expect(await screen.findByText('Exact-Env-Model')).toBeInTheDocument();
    expect(screen.getByText('ollama')).toBeInTheDocument();
    expect(screen.queryByText('claude-sonnet-4-5')).not.toBeInTheDocument();
  });
  it('does not invent an effective default from the saved credential list', async () => {
    renderWithProviders(
      <ConfigurationSummary
        effective={{
          ...effective,
          default_selection_key: null,
          configured_providers: [],
        }}
        onDetails={() => {}}
      />,
    );
    await waitFor(() => expect(api.listAiCredentials).toHaveBeenCalled());
    expect(screen.getByText('No default selected')).toBeInTheDocument();
  });
});
