// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EditProviderDialog } from '../EditProviderDialog/EditProviderDialog';
import { makeCredential, makeTestResult, renderWithProviders, SAMPLE_CATALOG } from './test-utils';

const listAiProviderCatalog = vi.fn();
const testAiCredentialUnsaved = vi.fn();
const updateAiCredential = vi.fn();

vi.mock('@/lib/api', () => ({
  listAiProviderCatalog: () => listAiProviderCatalog(),
  testAiCredentialUnsaved: (body: unknown) => testAiCredentialUnsaved(body),
  updateAiCredential: (id: number, body: unknown) => updateAiCredential(id, body),
}));

describe('EditProviderDialog', () => {
  beforeEach(() => {
    listAiProviderCatalog.mockResolvedValue(SAMPLE_CATALOG);
    testAiCredentialUnsaved.mockResolvedValue(makeTestResult({ provider: 'anthropic' }));
    updateAiCredential.mockResolvedValue(makeCredential());
  });

  it('tests candidate edits with the saved credential identity when key is blank', async () => {
    renderWithProviders(
      <EditProviderDialog credential={makeCredential({ id: 23 })} onClose={() => {}} />,
    );
    await screen.findByLabelText('API key');
    await userEvent.click(screen.getByRole('button', { name: /test connection/i }));
    await waitFor(() => expect(testAiCredentialUnsaved).toHaveBeenCalled());
    expect(testAiCredentialUnsaved.mock.calls[0][0]).toMatchObject({
      credential_id: 23,
      provider_name: 'anthropic',
      api_key: null,
      default_model: 'claude-sonnet-4-5',
    });
  });
});
