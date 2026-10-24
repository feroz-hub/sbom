// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BudgetCapsForm } from '../BudgetCapsForm/BudgetCapsForm';
import { SAMPLE_SETTINGS, renderWithProviders } from './test-utils';


const getAiCredentialSettings = vi.fn();
const updateAiCredentialSettings = vi.fn();

vi.mock('@/lib/api', () => ({
  getAiCredentialSettings: () => getAiCredentialSettings(),
  updateAiCredentialSettings: (body: unknown) => updateAiCredentialSettings(body),
}));


beforeEach(() => {
  getAiCredentialSettings.mockResolvedValue({ ...SAMPLE_SETTINGS });
  updateAiCredentialSettings.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});


describe('BudgetCapsForm', () => {
  it('renders the saved values', async () => {
    renderWithProviders(<BudgetCapsForm />);
    await waitFor(() =>
      expect(screen.getByLabelText(/per request/i)).toBeInTheDocument(),
    );
    expect((screen.getByLabelText(/per request/i) as HTMLInputElement).value).toBe('0.10');
    expect((screen.getByLabelText(/per scan/i) as HTMLInputElement).value).toBe('5.00');
  });

  it('blocks save when caps violate per_request ≤ per_scan ≤ daily', async () => {
    renderWithProviders(<BudgetCapsForm />);
    await waitFor(() =>
      expect(screen.getByLabelText(/per request/i)).toBeInTheDocument(),
    );

    const perRequest = screen.getByLabelText(/per request/i);
    await userEvent.clear(perRequest);
    await userEvent.type(perRequest, '100');

    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled();
    expect(updateAiCredentialSettings).not.toHaveBeenCalled();
  });

  it('saves on click when caps are valid', async () => {
    updateAiCredentialSettings.mockResolvedValue({ ...SAMPLE_SETTINGS, kill_switch_active: true });
    renderWithProviders(<BudgetCapsForm />);
    await waitFor(() =>
      expect(screen.getByLabelText(/per request/i)).toBeInTheDocument(),
    );

    const killSwitch = screen.getByLabelText(/kill switch/i);
    await userEvent.click(killSwitch);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => expect(updateAiCredentialSettings).toHaveBeenCalled());
    const body = updateAiCredentialSettings.mock.calls[0][0];
    expect(body.kill_switch_active).toBe(true);
  });
});
