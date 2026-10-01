// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import Page from './page';
const state = vi.hoisted(() => ({ tenant: '7', allowed: true, get: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: state.tenant, isLoading: false, hasPermission: () => state.allowed }) }));
vi.mock('@/lib/api', () => ({ getTenantAuditPage: (...args: unknown[]) => state.get(...args) }));
beforeEach(() => { state.allowed = true; state.tenant = '7'; state.get.mockReset().mockImplementation((_id, filters) => Promise.resolve({ items: [], total: 55, total_pages: 3, page: filters.page, page_size: filters.page_size })); });
function show() { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Page /></QueryClientProvider>); }
it('uses server-side pagination with 25 default rows and selectable page sizes', async () => {
  show(); expect(await screen.findByText(/55 matching events/)).toBeInTheDocument();
  expect(state.get.mock.calls[0][1]).toMatchObject({ page: 1, page_size: 25 });
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(state.get).toHaveBeenLastCalledWith(7, expect.objectContaining({ page: 2, page_size: 25 })));
  fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '50' } });
  await waitFor(() => expect(state.get).toHaveBeenLastCalledWith(7, expect.objectContaining({ page: 1, page_size: 50 })));
});
it('does not query tenant audit logs from platform context', () => {
  state.allowed = false; show(); expect(screen.getByRole('alert')).toBeInTheDocument(); expect(state.get).not.toHaveBeenCalled();
});
