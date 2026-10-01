// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { SidebarStatus } from './SidebarStatus';

vi.mock('@/lib/api', () => ({ getHealth: vi.fn().mockResolvedValue({ status: 'ok' }) }));
function show(compact = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><SidebarStatus compact={compact} /></QueryClientProvider>);
}
it('retains API health and readable status text in the integrated footer', async () => {
  show(); expect(await screen.findByText('API healthy')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  expect(screen.getByText('Checked just now')).toHaveClass('text-white/70');
});
it('exposes status text and a focusable tooltip in the collapsed footer', async () => {
  show(true); const status = await screen.findByLabelText('Status: API healthy');
  expect(status).toHaveAttribute('tabindex', '0');
  expect(status).toHaveAttribute('title', expect.stringContaining('API healthy'));
});
