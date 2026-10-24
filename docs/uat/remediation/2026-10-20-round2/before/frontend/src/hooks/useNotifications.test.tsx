// @vitest-environment jsdom

import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ApiError } from '@/lib/api';
import { ToastProvider } from './useToast';
import { useNotifications } from './useNotifications';

function Harness() {
  const notifications = useNotifications();
  return (
    <>
      <button onClick={() => notifications.showSuccess('Saved successfully.')}>success</button>
      <button onClick={() => notifications.showError('Save failed.')}>error</button>
      {[403, 409, 422, 500].map((status) => (
        <button
          key={status}
          onClick={() => notifications.showApiError(
            new ApiError(status === 409 ? 'A project with this name already exists.' : 'SQLAlchemy traceback secret', status),
            'Project creation failed.',
          )}
        >
          api-{status}
        </button>
      ))}
    </>
  );
}

function setup() {
  render(<ToastProvider><Harness /></ToastProvider>);
}

describe('useNotifications', () => {
  it('renders success and error variants in the DOM', () => {
    setup();
    fireEvent.click(screen.getByRole('button', { name: 'success' }));
    expect(screen.getByRole('status')).toHaveTextContent('Saved successfully.');
    fireEvent.click(screen.getByRole('button', { name: 'error' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Save failed.');
  });

  it.each([
    [403, 'You do not have permission to perform this action.'],
    [409, 'A project with this name already exists.'],
    [422, 'Please correct the highlighted fields.'],
    [500, 'The operation could not be completed because the service is temporarily unavailable.'],
  ])('renders a safe API %s notification', (status, expected) => {
    setup();
    fireEvent.click(screen.getByRole('button', { name: `api-${status}` }));
    expect(screen.getByRole('alert')).toHaveTextContent(expected);
    expect(document.body).not.toHaveTextContent('SQLAlchemy');
    expect(document.body).not.toHaveTextContent('traceback');
  });
});
