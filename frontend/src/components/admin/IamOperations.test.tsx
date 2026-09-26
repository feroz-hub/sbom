// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import IamOperations from './IamOperations';
let allowed = true;
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { isPlatformAdmin: allowed }, hasPermission: () => allowed }) }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); allowed = true; });
it('keeps operational data platform only', () => {
  allowed = false; const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); render(<IamOperations />);
  expect(screen.getByRole('alert')).toHaveTextContent('permission'); expect(fetch).not.toHaveBeenCalled();
});
it('shows safe counts and empty state', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ readiness: { ready: false, checks: { database: true, delivery_worker: false } }, delivery: { counts: { PENDING: 2, FAILED: 1 }, recent: [] } })));
  render(<IamOperations />); expect(screen.getByRole('status')).toHaveTextContent('Loading');
  expect(await screen.findByText('No security email deliveries recorded.')).toBeInTheDocument();
  expect(screen.getByText('Unavailable')).toBeInTheDocument(); expect(screen.getByText('PENDING')).toBeInTheDocument();
});
it('shows errors and retries', async () => {
  const fetch = vi.fn().mockResolvedValue(Response.json({}, { status: 503 })); vi.stubGlobal('fetch', fetch);
  render(<IamOperations />); await screen.findByRole('alert'); fireEvent.click(screen.getByRole('button', { name: 'Refresh health' }));
  expect(fetch).toHaveBeenCalledTimes(2);
});
