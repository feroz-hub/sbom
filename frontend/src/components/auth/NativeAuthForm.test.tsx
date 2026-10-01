// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { NativeAuthForm } from './NativeAuthForm';
vi.mock('./MicrosoftSignIn', () => ({ MicrosoftSignIn: () => null }));
const { replace } = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace }) }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.clearAllMocks(); window.history.replaceState(null, '', '/'); });

it('redirects successful activation to login with the email and removes the invitation token', async () => {
  window.history.replaceState(null, '', '/activate-account#token=invitation-token');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ success: true, email: 'user+invite@example.test' })));
  render(<NativeAuthForm activation />);
  fireEvent.change(screen.getByLabelText('Password', { exact: true }), { target: { value: 'new-password-123' } });
  fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'new-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Activate account' }));
  await waitFor(() => expect(replace).toHaveBeenCalledWith('/native-sign-in?email=user%2Binvite%40example.test&activated=1'));
  expect(window.location.hash).toBe('');
});

it('prefills the activated email while leaving the password empty', () => {
  render(<NativeAuthForm initialEmail="user@example.test" activated />);
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveValue('user@example.test');
  expect(screen.getByLabelText('Password', { exact: true })).toHaveValue('');
  expect(screen.getByRole('status')).toHaveTextContent('Account activated. Sign in with your new password.');
});

it('keeps failed activation on the form', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({}, { status: 400 })));
  render(<NativeAuthForm activation />);
  fireEvent.change(screen.getByLabelText('Password', { exact: true }), { target: { value: 'new-password-123' } });
  fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'new-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Activate account' }));
  await screen.findByText(/Unable to activate account/);
  expect(replace).not.toHaveBeenCalled();
});

it('keeps credentials accessible and lets users reveal only the entered password', async () => {
  const { container } = render(<NativeAuthForm />);
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveAttribute('autocomplete', 'username');
  const password = screen.getByLabelText('Password', { exact: true });
  expect(password).toHaveAttribute('autocomplete', 'current-password');
  fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
  expect(password).toHaveAttribute('type', 'text');
  fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
  expect(password).toHaveAttribute('type', 'password');
  expect(screen.getByRole('link', { name: 'Forgot password?' })).toHaveAttribute('href', '/forgot-password');
  expect((await axe(container)).violations).toEqual([]);
});

it('submits the existing login contract and hides server diagnostics', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ detail: 'SQL secret diagnostic' }, { status: 401 })));
  render(<NativeAuthForm />);
  fireEvent.change(screen.getByRole('textbox', { name: 'Email address' }), { target: { value: 'user@example.test' } });
  fireEvent.change(screen.getByLabelText('Password', { exact: true }), { target: { value: 'test-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await screen.findByText('The email address or password you entered is incorrect.');
  expect(fetch).toHaveBeenCalledWith('/api/auth/native/login', expect.objectContaining({ body: JSON.stringify({ email: 'user@example.test', password: 'test-password' }) }));
  expect(screen.queryByText(/SQL secret/)).not.toBeInTheDocument();
});

it('disables sign-in during a request and respects the existing HCL setting', async () => {
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'false');
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  render(<NativeAuthForm />);
  fireEvent.change(screen.getByRole('textbox', { name: 'Email address' }), { target: { value: 'user@example.test' } });
  fireEvent.change(screen.getByLabelText('Password', { exact: true }), { target: { value: 'test-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Signing in/ })).toBeDisabled());
  expect(screen.queryByRole('link', { name: /HCL.CS/ })).not.toBeInTheDocument();
});
