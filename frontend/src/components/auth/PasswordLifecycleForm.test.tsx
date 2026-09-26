// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PasswordLifecycleForm } from './PasswordLifecycleForm';
import { NativePasswordSettings } from './NativePasswordSettings';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/'); });
it('forgot response is generic and clears the email form', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ success: true })));
  render(<PasswordLifecycleForm mode="forgot" />);
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'person@example.test' } });
  fireEvent.click(screen.getByRole('button', { name: 'Send reset instructions' }));
  await screen.findByText('If an eligible account exists, password reset instructions will be sent.');
  expect(screen.getByLabelText('Email')).toHaveValue('');
});
it('reset uses fragment token only in POST and requires matching passwords', async () => {
  window.history.replaceState(null, '', '/reset-password#token=private-reset-proof');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ success: true })));
  render(<PasswordLifecycleForm mode="reset" />);
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'long new password' } });
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'different password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Update password' }));
  expect(screen.getByRole('status')).toHaveTextContent('Passwords must match.'); expect(fetch).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'long new password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Update password' }));
  await screen.findByText(/Password updated/);
  expect(fetch).toHaveBeenCalledWith('/api/auth/native/reset-password', expect.objectContaining({ body: JSON.stringify({ token: 'private-reset-proof', new_password: 'long new password' }) }));
  expect(window.location.hash).toBe(''); expect(screen.getByLabelText('New password')).toHaveValue('');
});
it('force change exposes only credential completion and correct autocomplete', async () => {
  window.history.replaceState(null, '', '/change-password?forced=1');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ authenticated: false })));
  render(<PasswordLifecycleForm mode="change" />);
  expect(await screen.findByLabelText('Current password')).toHaveAttribute('autocomplete', 'current-password');
  expect(screen.getByLabelText('New password')).toHaveAttribute('autocomplete', 'new-password');
  expect(screen.getByText(/requires a new password/)).toBeInTheDocument();
});
it('does not offer native settings for HCL sessions', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ authenticated: true, provider: 'HCL_CS' })));
  render(<NativePasswordSettings />);
  await waitFor(() => expect(fetch).toHaveBeenCalled());
  expect(screen.queryByRole('link', { name: 'Change password' })).not.toBeInTheDocument();
});
it('offers native settings for native sessions', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ authenticated: true, provider: 'NATIVE' })));
  render(<NativePasswordSettings />);
  expect(await screen.findByRole('link', { name: 'Change password' })).toHaveAttribute('href', '/change-password');
});
it('shows recoverable errors without echoing server diagnostics', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ detail: 'secret diagnostic' }, { status: 400 })));
  render(<PasswordLifecycleForm mode="forgot" />);
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'person@example.test' } });
  fireEvent.click(screen.getByRole('button', { name: 'Send reset instructions' }));
  await screen.findByText(/Unable to complete the request/);
  expect(screen.queryByText(/secret diagnostic/)).not.toBeInTheDocument();
});
