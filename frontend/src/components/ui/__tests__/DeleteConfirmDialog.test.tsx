// @vitest-environment jsdom
/**
 * DeleteConfirmDialog — behaviour + accessibility (Phase 4 §4.1, §4.4).
 *
 * Asserts:
 *   * Default radio is "Move to deleted" — onConfirm fires with permanent=false.
 *   * Switching to permanent reveals the typed-name confirmation input.
 *   * The Delete button stays disabled until the typed name matches.
 *   * The button label / variant switch ("Delete" → "Delete permanently").
 *   * Cascade-impact summary renders the prose form ("12 SBOMs and 87 runs").
 *   * vitest-axe reports zero violations on both states.
 */

import { describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeleteConfirmDialog } from '../DeleteConfirmDialog';

function renderDialog(overrides: Partial<Parameters<typeof DeleteConfirmDialog>[0]> = {}) {
  const onClose = vi.fn();
  const onConfirm = vi.fn();
  const utils = render(
    <DeleteConfirmDialog
      open
      onClose={onClose}
      onConfirm={onConfirm}
      recordName="Production Backend"
      recordKind="project"
      cascadeImpact={[
        { label: 'SBOM', count: 12 },
        { label: 'run', count: 87 },
        { label: 'finding', count: 4231 },
        { label: 'schedule', count: 0 },
      ]}
      {...overrides}
    />,
  );
  return { ...utils, onClose, onConfirm };
}

describe('DeleteConfirmDialog', () => {
  it('defaults to soft delete and confirms with permanent=false', async () => {
    const user = userEvent.setup();
    const { onConfirm } = renderDialog();

    expect(screen.getByLabelText(/move to deleted/i)).toBeChecked();
    expect(screen.queryByLabelText(/type production backend to confirm/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    expect(onConfirm).toHaveBeenCalledWith({ permanent: false });
  });

  it('shows the typed-name confirmation when permanent is selected', async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(screen.getByLabelText(/delete permanently/i));
    expect(screen.getByLabelText(/type production backend to confirm/i)).toBeInTheDocument();
    // Button label flips
    expect(screen.getByRole('button', { name: /delete permanently/i })).toBeInTheDocument();
  });

  it('disables permanent confirm until the typed name matches exactly', async () => {
    const user = userEvent.setup();
    const { onConfirm } = renderDialog();

    await user.click(screen.getByLabelText(/delete permanently/i));

    const button = screen.getByRole('button', { name: /delete permanently/i });
    expect(button).toBeDisabled();

    const input = screen.getByLabelText(/type production backend to confirm/i);
    fireEvent.change(input, { target: { value: 'Production Backen' } });
    expect(button).toBeDisabled();

    fireEvent.change(input, { target: { value: 'Production Backend' } });
    expect(button).not.toBeDisabled();

    await user.click(button);
    expect(onConfirm).toHaveBeenCalledWith({ permanent: true });
  });

  it('renders cascade impact summary in prose form', () => {
    renderDialog();
    // Zero-count items are filtered out — schedule shouldn't appear
    expect(screen.getAllByText(/12 SBOMs/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/87 runs/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/0 schedules?/i)).not.toBeInTheDocument();
  });

  it('hides cascade impact paragraph when no children are reported', () => {
    renderDialog({ cascadeImpact: [], recordKind: 'schedule' });
    // No "X SBOMs" prose at all
    expect(screen.queryByText(/and its/i)).not.toBeInTheDocument();
  });

  it('hides the permanent option when allowPermanent=false', () => {
    renderDialog({ allowPermanent: false });
    expect(screen.queryByLabelText(/delete permanently/i)).not.toBeInTheDocument();
  });

  it('has zero axe violations in the soft-default state', async () => {
    const { container } = renderDialog();
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });

  it('has zero axe violations in the permanent + typed-confirm state', async () => {
    const user = userEvent.setup();
    const { container } = renderDialog();
    await user.click(screen.getByLabelText(/delete permanently/i));
    fireEvent.change(
      screen.getByLabelText(/type production backend to confirm/i),
      { target: { value: 'Production Backend' } },
    );
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
