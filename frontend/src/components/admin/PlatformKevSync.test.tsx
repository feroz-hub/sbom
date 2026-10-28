// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { PlatformKevSync } from './PlatformKevSync';

const state = vi.hoisted(() => ({ platform: true, allowed: true, sync: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ isPlatformContext: state.platform }) }));
vi.mock('@/hooks/usePermission', () => ({ usePermissions: () => ({ can: (permission: string) => state.allowed && permission === 'platform:admin', permissionsLoaded: true }) }));
vi.mock('@/lib/api', () => ({ syncKevCatalog: () => state.sync() }));
beforeEach(() => { state.platform = true; state.allowed = true; state.sync.mockReset().mockResolvedValue({ ok: true }); });
function mount() {
  const qc = new QueryClient();
  const invalidate = vi.spyOn(qc, 'invalidateQueries');
  render(<QueryClientProvider client={qc}><ToastProvider><PlatformKevSync /></ToastProvider></QueryClientProvider>);
  return invalidate;
}
it('allows platform synchronization and invalidates every KEV surface', async () => {
  const invalidate = mount();
  fireEvent.click(screen.getByRole('button', { name: 'Sync KEV Catalog' }));
  await waitFor(() => expect(state.sync).toHaveBeenCalledTimes(1));
  for (const key of ['kev-catalog', 'kev-filter-options', 'kev-detail']) expect(invalidate).toHaveBeenCalledWith({ queryKey: [key] });
});
it.each([[false, true], [true, false], [false, false]])('requires platform context %s and effective permission %s', (platform, allowed) => {
  state.platform = platform; state.allowed = allowed; mount();
  expect(screen.queryByRole('button', { name: 'Sync KEV Catalog' })).not.toBeInTheDocument();
  expect(state.sync).not.toHaveBeenCalled();
});
