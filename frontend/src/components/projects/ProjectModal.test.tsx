// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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
  const rendered = render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider><ProjectModal open onClose={onClose} /></ToastProvider>
    </QueryClientProvider>,
  );
  return { onClose, queryClient, unmount: rendered.unmount };
}

describe('ProjectModal notifications', () => {
  beforeEach(() => {
    vi.mocked(createProject).mockReset();
  });

  it('renders a visible success toast after backend confirmation and closes the modal', async () => {
    const user = userEvent.setup();
    vi.mocked(createProject).mockResolvedValue({ id: 9, project_name: 'Visible Toast' } as never);
    const { onClose, queryClient, unmount } = renderModal();
    await user.type(screen.getByRole('textbox', { name: 'Project Name' }), 'Visible Toast');
    await user.click(screen.getByRole('button', { name: 'Create Project' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Project “Visible Toast” was created successfully.');
    expect(onClose).toHaveBeenCalledTimes(1);
    unmount();
    queryClient.clear();
  });

  it('keeps the modal open and renders a mapped conflict toast on failure', async () => {
    let rejectRequest: (reason?: unknown) => void = () => undefined;
    vi.mocked(createProject).mockImplementation(
      () => new Promise((_resolve, reject) => { rejectRequest = reject; }),
    );
    const { onClose, queryClient, unmount } = renderModal();
    fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), {
      target: { value: 'Duplicate' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    await waitFor(() => expect(createProject).toHaveBeenCalledTimes(1));
    rejectRequest(new ApiError('A project with this name already exists.', 409));
    expect(await screen.findByRole('alert')).toHaveTextContent('A project with this name already exists.');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    unmount();
    queryClient.clear();
  });

  it('disables submission while the request is pending', async () => {
    let resolveRequest: (value: unknown) => void = () => undefined;
    vi.mocked(createProject).mockReturnValue(
      new Promise((resolve) => { resolveRequest = resolve; }) as ReturnType<typeof createProject>,
    );
    const { queryClient, unmount } = renderModal();
    fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), {
      target: { value: 'Pending' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    await waitFor(() => expect(screen.getByRole('button', { name: /Create Project/ })).toBeDisabled());
    resolveRequest({ id: 10, project_name: 'Pending' });
    unmount();
    queryClient.clear();
  });
});
