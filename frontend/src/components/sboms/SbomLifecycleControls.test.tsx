// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SBOMSource } from '@/types';

const state = vi.hoisted(() => ({ admin: true, permission: true }));
const api = vi.hoisted(() => ({ change: vi.fn(), history: vi.fn(), toast: vi.fn(), invalidate: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { roles: state.admin ? ['TENANT_ADMIN'] : ['VIEWER'], isPlatformAdmin: false }, hasPermission: () => state.permission, isLoading: false }) }));
vi.mock('@/hooks/useToast', () => ({ useToast: () => ({ showToast: api.toast }) }));
vi.mock('@/lib/api', () => ({ changeSbomLifecycle: api.change, getSbomLifecycleHistory: api.history }));
vi.mock('@/lib/queryInvalidation', () => ({ invalidateSbomLifecycle: api.invalidate }));
import { SbomLifecycleControls } from './SbomLifecycleControls';
import { sbomEligibility } from '@/lib/sbomEligibility';

const sbom = { id: 7, sbom_name: 'product-sbom', status: 'validated', lifecycle_status: 'ACTIVE' } as SBOMSource;
function mount(record = sbom) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={qc}><SbomLifecycleControls sbom={record} showHistory /></QueryClientProvider>);
  return qc;
}
beforeEach(() => { vi.clearAllMocks(); state.admin = true; state.permission = true; api.history.mockResolvedValue([]); });

describe('SBOM operational lifecycle', () => {
  it.each([['ACTIVE', 'Mark Inactive', 'INACTIVE'], ['INACTIVE', 'Mark Active', 'ACTIVE']] as const)('requires a reason to transition %s', async (status, label, target) => {
    api.change.mockResolvedValue({ ...sbom, lifecycle_status: target });
    const qc = mount({ ...sbom, lifecycle_status: status });
    expect(screen.getByText(status)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: label }));
    const dialog = screen.getByRole('dialog');
    const submit = within(dialog).getByRole('button', { name: label });
    expect(submit).toBeDisabled();
    const reason = within(dialog).getByLabelText('Reason (required)');
    expect(reason).toBeRequired();
    fireEvent.change(reason, { target: { value: '   ' } });
    expect(submit).toBeDisabled();
    fireEvent.change(reason, { target: { value: '  Portfolio retirement  ' } });
    fireEvent.click(submit);
    await waitFor(() => expect(api.change).toHaveBeenCalledWith(7, target, 'Portfolio retirement'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(qc.getQueryData(['sbom', 7])).toEqual({ ...sbom, lifecycle_status: target });
    expect(api.invalidate).toHaveBeenCalled();
  });

  it('hides modification controls for non-administrators even with a permission', () => {
    state.admin = false;
    mount({ ...sbom, lifecycle_status: 'INACTIVE' });
    expect(screen.getByText('INACTIVE')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Mark Active' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Lifecycle history' })).toBeEnabled();
  });

  it('requires the existing administrator permission', () => {
    state.permission = false;
    mount();
    expect(screen.queryByRole('button', { name: 'Mark Inactive' })).not.toBeInTheDocument();
  });

  it('retains reason and shows an API failure without falsely changing status', async () => {
    api.change.mockRejectedValue(Object.assign(new Error('Change rejected'), { status: 409 }));
    const qc = mount();
    fireEvent.click(screen.getByRole('button', { name: 'Mark Inactive' }));
    fireEvent.change(screen.getByLabelText('Reason (required)'), { target: { value: 'Retirement' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Mark Inactive' }));
    expect(await screen.findByText('Change rejected')).toBeVisible();
    expect(screen.getByLabelText('Reason (required)')).toHaveValue('Retirement');
    expect(qc.getQueryData(['sbom', 7])).toBeUndefined();
    expect(api.invalidate).not.toHaveBeenCalled();
  });

  it('loads readable audit history only when requested', async () => {
    api.history.mockResolvedValue([{ id: 1, old_status: 'ACTIVE', new_status: 'INACTIVE', reason: 'Product retired', actor: 'admin', timestamp: '2026-10-05T00:00:00Z' }]);
    mount();
    expect(api.history).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Lifecycle history' }));
    expect(await screen.findByText('Product retired')).toBeVisible();
    expect(screen.getByText('ACTIVE → INACTIVE')).toBeVisible();
  });

  it.each([['quarantined', 'SBOM_UNSAFE'], ['pending', 'SBOM_VALIDATION_PENDING'], ['failed', 'SBOM_VALIDATION_BLOCKED']] as const)('matches backend eligibility for %s', (status, code) => {
    expect(sbomEligibility({ ...sbom, status }).reason_code).toBe(code);
  });
  it('blocks inactive records despite a cached eligible verdict', () => {
    expect(sbomEligibility({ ...sbom, lifecycle_status: 'INACTIVE', processing_eligibility: { eligible: true, reason: null, reason_code: null } }).reason_code).toBe('SBOM_INACTIVE');
    expect(sbomEligibility({ ...sbom, error_count: 1 }).eligible).toBe(false);
    expect(sbomEligibility({ ...sbom, validation_errors: [{ severity: 'error' }] as SBOMSource['validation_errors'] }).eligible).toBe(false);
  });
});
