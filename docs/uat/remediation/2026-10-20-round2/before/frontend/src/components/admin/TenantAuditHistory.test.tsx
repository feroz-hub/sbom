// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { TenantAuditHistory } from './TenantAuditHistory';
const get = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ getTenantAuditHistory: (...args: unknown[]) => get(...args) }));
it('shows at most five humanized administrative events and links to full audit logs', async () => {
  get.mockResolvedValue(Array.from({ length: 8 }, (_, id) => ({ id, action: 'TENANT_MEMBER_ADDED', label: 'Member added', timestamp: '2026-10-01T00:00:00Z', outcome: 'SUCCESS', correlation_id: 'secret-technical-correlation' })));
  render(<QueryClientProvider client={new QueryClient()}><TenantAuditHistory tenantId={7} /></QueryClientProvider>);
  expect(await screen.findAllByText('Member added')).toHaveLength(5);
  expect(screen.getByText('Recent Audit Activity')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'View all audit logs →' })).toHaveAttribute('href', '/settings/users/audit');
  expect(screen.queryByText('secret-technical-correlation')).not.toBeInTheDocument();
  expect(get).toHaveBeenCalledWith(7);
});
