// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import LoggedOutPage from './page';

it('renders the logout confirmation and explicit sign-in action', () => {
  render(<LoggedOutPage />);
  expect(screen.getByRole('heading', { name: 'Signed out successfully' })).toBeInTheDocument();
  expect(screen.getByText('Your SBOM Analyzer session has ended.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Sign in again' })).toHaveAttribute('href', '/api/auth/login?returnTo=%2F');
});
