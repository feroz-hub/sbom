// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { ScheduleEditor } from './ScheduleEditor';

const api = vi.hoisted(() => ({
  upsertProjectSchedule: vi.fn(),
  upsertSbomSchedule: vi.fn(),
  upsertScopedSchedule: vi.fn(),
}));

vi.mock('@/lib/api', () => api);

function wrap(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{node}</ToastProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.upsertProjectSchedule.mockResolvedValue({});
  api.upsertSbomSchedule.mockResolvedValue({});
  api.upsertScopedSchedule.mockResolvedValue({});
});

describe('ScheduleEditor hierarchical scopes', () => {
  it.each(['PROJECT', 'PRODUCT'] as const)('shows target policy for %s schedules', (scope) => {
    render(wrap(<ScheduleEditor open onClose={vi.fn()} scope={scope} targetId={42} />));
    expect(screen.getByLabelText('Target versions')).toBeInTheDocument();
    expect(screen.getByLabelText('Minimum analysis gap (minutes)')).toBeInTheDocument();
  });

  it('hides target policy for an exact SBOM schedule', () => {
    render(wrap(<ScheduleEditor open onClose={vi.fn()} scope="SBOM" targetId={81} />));
    expect(screen.queryByLabelText('Target versions')).not.toBeInTheDocument();
  });

  it('saves a Product schedule with the selected policy and gap', async () => {
    render(wrap(<ScheduleEditor open onClose={vi.fn()} scope="PRODUCT" targetId={22} />));
    fireEvent.change(screen.getByLabelText('Target versions'), { target: { value: 'ALL_ACTIVE_VERSIONS' } });
    fireEvent.change(screen.getByLabelText('Minimum analysis gap (minutes)'), { target: { value: '120' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create schedule' }));

    await waitFor(() => expect(api.upsertScopedSchedule).toHaveBeenCalled());
    expect(api.upsertScopedSchedule).toHaveBeenCalledWith(
      'PRODUCT',
      22,
      expect.objectContaining({
        target_version_policy: 'ALL_ACTIVE_VERSIONS',
        min_gap_minutes: 120,
        mode: 'CUSTOM',
      }),
    );
  });
});
