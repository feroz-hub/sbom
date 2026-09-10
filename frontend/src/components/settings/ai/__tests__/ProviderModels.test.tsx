// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ProviderModels } from '../ProvidersList/ProviderModels';
import { renderWithProviders } from './test-utils';

const listAiProviderModels = vi.fn();
const refreshAiProviderModels = vi.fn();
const selectAiProviderModel = vi.fn();
const testAiProviderModel = vi.fn();

vi.mock('@/lib/api', () => ({
  listAiProviderModels: (...args: unknown[]) => listAiProviderModels(...args),
  refreshAiProviderModels: (...args: unknown[]) => refreshAiProviderModels(...args),
  selectAiProviderModel: (...args: unknown[]) => selectAiProviderModel(...args),
  testAiProviderModel: (...args: unknown[]) => testAiProviderModel(...args),
}));

const model = {
  id: 7,
  provider_credential_id: 3,
  provider_name: 'gemini',
  provider_model_id: 'models/gemini-new',
  runtime_model_id: 'gemini-new',
  display_name: 'Gemini New',
  is_available: true,
  is_enabled: true,
  is_selected: false,
  supports_chat: true,
  supports_structured_output: null,
  supports_streaming: false,
  supports_tools: null,
  context_window: 1000,
  max_output_tokens: 100,
  discovery_source: 'live',
  first_discovered_at: '2026-09-09T00:00:00Z',
  last_discovered_at: '2026-09-09T00:00:00Z',
  last_verified_at: null,
  last_test_success: null,
  last_test_error: null,
};

beforeEach(() => {
  listAiProviderModels.mockReset().mockResolvedValue([model]);
  refreshAiProviderModels.mockReset().mockResolvedValue({ discovered: 2, created: 1, updated: 1, unavailable: 0 });
  selectAiProviderModel.mockReset().mockResolvedValue({ ...model, is_selected: true });
  testAiProviderModel.mockReset().mockResolvedValue({ success: true, error_message: null });
});

describe('ProviderModels', () => {
  it('shows normalized/provider IDs, capabilities, and explicit actions', async () => {
    renderWithProviders(<ProviderModels credentialId={3} providerName="Gemini" enabled />);
    expect(await screen.findByText('gemini-new')).toBeInTheDocument();
    expect(screen.getByText(/Provider ID: models\/gemini-new/)).toBeInTheDocument();
    expect(screen.getByText('chat: yes')).toBeInTheDocument();
    expect(screen.queryByText(/JSON:/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Set active' }));
    await waitFor(() => expect(selectAiProviderModel).toHaveBeenCalledWith(3, 7));
  });

  it('refreshes without selecting a newly discovered model', async () => {
    renderWithProviders(<ProviderModels credentialId={3} providerName="Gemini" enabled />);
    await screen.findByText('gemini-new');
    await userEvent.click(screen.getByRole('button', { name: /refresh models/i }));
    await waitFor(() => expect(refreshAiProviderModels).toHaveBeenCalledWith(3));
    expect(selectAiProviderModel).not.toHaveBeenCalled();
  });
});
