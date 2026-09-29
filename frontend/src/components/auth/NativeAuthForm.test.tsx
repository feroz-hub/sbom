// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { NativeAuthForm } from './NativeAuthForm';
vi.mock('./MicrosoftSignIn', () => ({ MicrosoftSignIn: () => null }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

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
