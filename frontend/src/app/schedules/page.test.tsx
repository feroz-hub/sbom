// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type { AnalysisSchedule } from '@/types';
import SchedulesPage from './page';

const api = vi.hoisted(() => ({
  deleteProjectSchedule: vi.fn(),
  deleteSbomSchedule: vi.fn(),
  deleteScopedSchedule: vi.fn(),
  getProjects: vi.fn(),
  getSboms: vi.fn(),
  listSchedules: vi.fn(),
  pauseSchedule: vi.fn(),
  previewScheduleTargets: vi.fn(),
  resumeSchedule: vi.fn(),
  runScheduleNow: vi.fn(),
}));

vi.mock('@/lib/api', () => api);
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title }: { title: string }) => <h1>{title}</h1> }));
vi.mock('@/components/schedules/ScheduleEditor', () => ({ ScheduleEditor: () => null }));

const productSchedule: AnalysisSchedule = {
  id: 12,
  tenant_id: 1,
  scope: 'PRODUCT',
  project_id: null,
  product_id: 22,
  sbom_id: null,
  cadence: 'DAILY',
  cron_expression: null,
  day_of_week: null,
  day_of_month: null,
  hour_utc: 2,
  timezone: 'UTC',
  mode: 'CUSTOM',
  target_version_policy: 'CURRENT_ONLY',
  state: 'CUSTOM',
  enabled: true,
  next_run_at: '2026-09-08T02:00:00+00:00',
  last_run_at: null,
  last_run_status: null,
  last_run_id: null,
  consecutive_failures: 0,
  min_gap_minutes: 60,
  created_on: null,
  created_by: null,
  modified_on: null,
  modified_by: null,
  product_name: 'Infusion Pump Controller',
};

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
  api.listSchedules.mockResolvedValue([productSchedule]);
  api.getProjects.mockResolvedValue([]);
  api.getSboms.mockResolvedValue([]);
  api.previewScheduleTargets.mockResolvedValue({ schedule_id: 12, scope: 'PRODUCT', target_count: 0, skipped_count: 0, targets: [] });
});

it('renders Product schedules by name and sends the PRODUCT scope filter', async () => {
  render(wrap(<SchedulesPage />));
  expect(await screen.findByText('Infusion Pump Controller')).toBeInTheDocument();
  expect(screen.getByText('PRODUCT')).toBeInTheDocument();
  expect(screen.getByText('Current only')).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'PRODUCT' } });
  await waitFor(() =>
    expect(api.listSchedules).toHaveBeenLastCalledWith(
      expect.objectContaining({ scope: 'PRODUCT' }),
      expect.any(AbortSignal),
    ),
  );
});
