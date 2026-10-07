// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/api';
const api = vi.hoisted(() => ({ getAdvisorPolicy: vi.fn(), getAdvisorPolicyHistory: vi.fn(), publishAdvisorPolicy: vi.fn() }));
let tenantId = 1;
let canRead = true;
let platformRead = true;
let canUpdate = true;
vi.mock('@/lib/advisorPolicyApi', () => api);
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: tenantId, activeTenant: { name: `Tenant ${tenantId}` }, hasPermission: (p: string) => p.startsWith('platform:') && !platformRead ? false : p.endsWith(':read') ? canRead : canUpdate, isLoading: false }) }));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: () => null }));
import Page from './page';
import PlatformPage from '../../platform/configuration/advisor-policies/page';
const state = { configured: false, effective: null, tenant_override: null, platform_default: null, row_version: 0 };
function wrapper({ children }: { children: React.ReactNode }) { return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{children}</QueryClientProvider>; }
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); tenantId = 1; canRead = true; platformRead = true; canUpdate = true; api.getAdvisorPolicy.mockResolvedValue(state); api.getAdvisorPolicyHistory.mockResolvedValue({ items: [] }); api.publishAdvisorPolicy.mockResolvedValue({ ...state, row_version: 1 }); });
async function fill() { const user = userEvent.setup(); await screen.findByLabelText('Accepted risk policy mode'); await user.selectOptions(screen.getByLabelText('Accepted risk policy mode'), 'ACTIVE'); await user.type(screen.getByLabelText('Accepted risk reason'), 'Approved risk threshold'); return user; }
describe('Tenant advisor policies', () => {
  it('publishes platform defaults without tenant context or inheritance mode', async () => { render(<PlatformPage />, { wrapper }); const user = await fill(); expect(screen.queryByRole('option', { name: 'Inherit platform default' })).not.toBeInTheDocument(); await user.click(screen.getAllByRole('button', { name: 'Publish policy version' })[0]); await waitFor(() => expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(null, 'accepted-risk', expect.objectContaining({ status: 'ACTIVE' }))); });
  it('denies platform configuration to a tenant administrator', () => { platformRead = false; render(<PlatformPage />, { wrapper }); expect(screen.getByRole('alert')).toHaveTextContent('not permitted'); expect(api.getAdvisorPolicy).not.toHaveBeenCalled(); });
  it('publishes a version scoped to the active tenant with concurrency token', async () => { render(<Page />, { wrapper }); const user = await fill(); await user.click(screen.getAllByRole('button', { name: 'Publish policy version' })[0]); await waitFor(() => expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(1, 'accepted-risk', expect.objectContaining({ status: 'ACTIVE', row_version: 0, reason: 'Approved risk threshold', rules: expect.objectContaining({ max_actionable_severity: 'MEDIUM' }) }))); expect(await screen.findByRole('status')).toHaveTextContent('published'); });
  it.each(['INHERIT', 'DISABLED'])('publishes %s without active rules', async (status) => { render(<Page />, { wrapper }); const user = userEvent.setup(); await screen.findByLabelText('Accepted risk policy mode'); await user.selectOptions(screen.getByLabelText('Accepted risk policy mode'), status); await user.type(screen.getByLabelText('Accepted risk reason'), 'Change tenant mode'); await user.click(screen.getAllByRole('button', { name: 'Publish policy version' })[0]); await waitFor(() => expect(api.publishAdvisorPolicy).toHaveBeenCalledWith(1, 'accepted-risk', { status, rules: null, reason: 'Change tenant mode', row_version: 0 })); });
  it('rejects malformed JSON before a write', async () => { render(<Page />, { wrapper }); const user = await fill(); await user.clear(screen.getByLabelText('Accepted risk rules')); await user.type(screen.getByLabelText('Accepted risk rules'), 'invalid'); await user.click(screen.getAllByRole('button', { name: 'Publish policy version' })[0]); expect(await screen.findByRole('alert')).toBeInTheDocument(); expect(api.publishAdvisorPolicy).not.toHaveBeenCalled(); });
  it('allows analysts to read without publishing', async () => { canUpdate = false; render(<Page />, { wrapper }); await screen.findByLabelText('Accepted risk policy mode'); expect(screen.getByLabelText('Accepted risk policy mode')).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Publish policy version' })).not.toBeInTheDocument(); });
  it('does not fetch without read permission', () => { canRead = false; render(<Page />, { wrapper }); expect(screen.getByRole('alert')).toHaveTextContent('not permitted'); expect(api.getAdvisorPolicy).not.toHaveBeenCalled(); });
  it('blocks stale writes until the latest policy is reloaded', async () => { api.publishAdvisorPolicy.mockRejectedValue(new ApiError('Conflict', 409)); render(<Page />, { wrapper }); const user = await fill(); await user.click(screen.getAllByRole('button', { name: 'Publish policy version' })[0]); expect(await screen.findByRole('alert')).toHaveTextContent('Another administrator'); expect(screen.getByLabelText('Accepted risk policy mode')).toBeDisabled(); api.getAdvisorPolicy.mockResolvedValue({ ...state, row_version: 2 }); await user.click(screen.getByRole('button', { name: /Reload latest/ })); await waitFor(() => expect(screen.getByLabelText('Accepted risk policy mode')).not.toBeDisabled()); });
  it('discards the prior tenant draft on a tenant switch', async () => { const rendered = render(<Page />, { wrapper }); await fill(); tenantId = 2; rendered.rerender(<Page />); await waitFor(() => expect(api.getAdvisorPolicy).toHaveBeenCalledWith(2, 'accepted-risk')); expect(await screen.findByLabelText('Accepted risk reason')).toHaveValue(''); });
});
