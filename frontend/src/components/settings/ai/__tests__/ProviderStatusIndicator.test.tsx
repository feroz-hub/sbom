// @vitest-environment jsdom

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ProviderStatusIndicator } from '../ProvidersList/ProviderStatusIndicator';
import { makeCredential } from './test-utils';


describe('ProviderStatusIndicator', () => {
  it('renders Disabled when enabled=false', () => {
    render(<ProviderStatusIndicator credential={makeCredential({ enabled: false })} />);
    const el = screen.getByRole('status');
    expect(el).toHaveAttribute('data-status', 'disabled');
    expect(el).toHaveTextContent(/Disabled/);
  });

  it('renders Not tested when last_test_at is null', () => {
    render(
      <ProviderStatusIndicator
        credential={makeCredential({ last_test_at: null, last_test_success: null })}
      />,
    );
    const el = screen.getByRole('status');
    expect(el).toHaveAttribute('data-status', 'untested');
  });

  it('renders OK when last_test_success=true', () => {
    render(<ProviderStatusIndicator credential={makeCredential({ last_test_success: true })} />);
    expect(screen.getByRole('status')).toHaveAttribute('data-status', 'ok');
  });

  it('renders Failing with error tooltip when last_test_success=false', () => {
    render(
      <ProviderStatusIndicator
        credential={makeCredential({
          last_test_success: false,
          last_test_error: 'Bad API key',
        })}
      />,
    );
    const el = screen.getByRole('status');
    expect(el).toHaveAttribute('data-status', 'failing');
    expect(el).toHaveTextContent(/Failing/);
    expect(el.getAttribute('title') ?? '').toMatch(/Bad API key/);
  });
});
