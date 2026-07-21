// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { ApiError, createProject } from '@/lib/api';
import { ProjectModal } from './ProjectModal';

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, createProject: vi.fn(), updateProject: vi.fn() };
});

function renderModal(onClose = vi.fn()) {
  const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false }, queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider><ProjectModal open onClose={onClose} /></ToastProvider>
    </QueryClientProvider>,
  );
  return { onClose, queryClient };
}

describe('ProjectModal notifications', () => {
  beforeEach(() => vi.mocked(createProject).mockReset());

  it('renders a visible success toast after backend confirmation and closes the modal', async () => {
    vi.mocked(createProject).mockResolvedValue({ id: 9, project_name: 'Visible Toast' } as never);
    const { onClose } = renderModal();
    fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'Visible Toast' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Project “Visible Toast” was created successfully.');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps the modal open and renders a mapped conflict toast on failure', async () => {
    vi.mocked(createProject).mockRejectedValue(new ApiError('A project with this name already exists.', 409));
    const { onClose } = renderModal();
    fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'Duplicate' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('A project with this name already exists.');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('disables submission while the request is pending', async () => {
    vi.mocked(createProject).mockReturnValue(new Promise(() => undefined));
    renderModal();
    fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'Pending' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    await waitFor(() => expect(screen.getByRole('button', { name: /Create Project/ })).toBeDisabled());
  });
});
