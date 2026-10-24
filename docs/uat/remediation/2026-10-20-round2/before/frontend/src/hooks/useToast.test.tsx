// @vitest-environment jsdom

import { useState } from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ToastProvider, useToast } from './useToast';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';

function Harness() {
  const { showToast } = useToast();
  return (
    <div>
      <button onClick={() => showToast('Saved once.', 'success')}>success</button>
      <button onClick={() => showToast('Permission denied.', 'error')}>error</button>
    </div>
  );
}

function DialogHarness() {
  const { showToast } = useToast();
  return (
    <>
      <ConfirmationDialog
        open
        title="Delete project"
        description="This cannot be undone."
        confirmLabel="Delete"
        onConfirm={() => showToast('Deletion failed safely.', 'error')}
        onClose={() => undefined}
      />
    </>
  );
}

function NavigatingHarness() {
  const [onDestination, setOnDestination] = useState(false);
  const { showToast } = useToast();
  return (
    <button onClick={() => { showToast('Survives navigation.', 'success'); setOnDestination(true); }}>
      {onDestination ? 'Destination' : 'Navigate'}
    </button>
  );
}

describe('ToastProvider', () => {
  it('renders the first direct success notification visibly', () => {
    render(<ToastProvider><Harness /></ToastProvider>);
    fireEvent.click(screen.getByText('success'));
    expect(screen.getByRole('status')).toBeVisible();
    expect(screen.getByRole('status')).toHaveTextContent('Saved once.');
  });

  it('suppresses duplicate identical notifications', () => {
    render(<ToastProvider><Harness /></ToastProvider>);
    fireEvent.click(screen.getByText('success'));
    fireEvent.click(screen.getByText('success'));
    expect(screen.getAllByText('Saved once.')).toHaveLength(1);
  });

  it('announces errors and provides a keyboard-accessible dismiss action', () => {
    render(<ToastProvider><Harness /></ToastProvider>);
    fireEvent.click(screen.getByText('error'));
    expect(screen.getByRole('alert')).toHaveTextContent('Permission denied.');
    expect(document.body.querySelector('[data-toast-container]')).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('Permission denied.')).not.toBeInTheDocument();
  });

  it('auto-dismisses success notifications', () => {
    vi.useFakeTimers();
    try {
      render(<ToastProvider><Harness /></ToastProvider>);
      fireEvent.click(screen.getByText('success'));
      act(() => vi.advanceTimersByTime(3999));
      expect(screen.getByText('Saved once.')).toBeVisible();
      act(() => vi.advanceTimersByTime(1));
      expect(screen.queryByText('Saved once.')).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('renders over an open confirmation dialog', () => {
    render(<ToastProvider><DialogHarness /></ToastProvider>);
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Deletion failed safely.');
    expect(document.body.querySelector('[data-toast-container]')).not.toBeNull();
  });

  it('persists when the notifying route content changes', () => {
    render(<ToastProvider><NavigatingHarness /></ToastProvider>);
    fireEvent.click(screen.getByRole('button', { name: 'Navigate' }));
    expect(screen.getByRole('button', { name: 'Destination' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Survives navigation.');
  });
});
