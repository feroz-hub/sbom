// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import LoggedOutPage from './page';

afterEach(() => vi.unstubAllEnvs());

it('renders the logout confirmation and explicit HCL sign-in action', async () => {
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'true');
  render(await LoggedOutPage({}));
  expect(screen.getByRole('heading', { name: 'Signed out successfully' })).toBeInTheDocument();
  expect(screen.getByText('Your SBOM Analyzer session has ended.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Sign in again' })).toHaveAttribute('href', '/api/auth/login?returnTo=%2F');
});

it.each(['native', undefined])('uses Native sign-in in Native-only mode (hint=%s)', async provider => {
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'false');
  render(await LoggedOutPage({ searchParams: Promise.resolve({ provider }) }));
  expect(screen.getByRole('link', { name: 'Sign in again' })).toHaveAttribute('href', '/native-sign-in');
});

it('keeps Native users on Native sign-in when HCL is also enabled', async () => {
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'true');
  render(await LoggedOutPage({ searchParams: Promise.resolve({ provider: 'native' }) }));
  expect(screen.getByRole('link', { name: 'Sign in again' })).toHaveAttribute('href', '/native-sign-in');
});
