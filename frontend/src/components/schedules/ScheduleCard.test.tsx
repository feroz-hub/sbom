// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type { AnalysisSchedule } from '@/types';
import { ScheduleCard } from './ScheduleCard';

const api = vi.hoisted(() => ({
  deleteProjectSchedule: vi.fn(),
  deleteProductSchedule: vi.fn(),
  deleteSbomSchedule: vi.fn(),
  excludeFromParentSchedule: vi.fn(),
  getEffectiveProductSchedule: vi.fn(),
  getProjectSchedule: vi.fn(),
  getSbomSchedule: vi.fn(),
  pauseSchedule: vi.fn(),
  previewScheduleTargets: vi.fn(),
  restoreScheduleInheritance: vi.fn(),
  resumeSchedule: vi.fn(),
  runScheduleNow: vi.fn(),
}));

vi.mock('@/lib/api', () => ({ ...api, HttpError: class HttpError extends Error { status = 500; } }));
vi.mock('./ScheduleEditor', () => ({
  ScheduleEditor: ({
    open,
    existing,
  }: {
    open: boolean;
    existing?: { id: number } | null;
  }) => open ? (
    <div data-testid="schedule-editor" data-existing-id={existing?.id ?? 'new'}>
      Schedule editor
    </div>
  ) : null,
}));

const schedule: AnalysisSchedule = {
  id: 7,
  tenant_id: 1,
  scope: 'PROJECT',
  project_id: 3,
  product_id: null,
  sbom_id: null,
  cadence: 'WEEKLY',
  cron_expression: null,
  day_of_week: 0,
  day_of_month: null,
  hour_utc: 2,
  timezone: 'UTC',
  mode: 'CUSTOM',
  target_version_policy: 'CURRENT_ONLY',
  state: 'CUSTOM',
  enabled: true,
  next_run_at: '2026-09-14T02:00:00+00:00',
  last_run_at: null,
  last_run_status: null,
  last_run_id: null,
  consecutive_failures: 0,
  min_gap_minutes: 60,
  created_on: null,
  created_by: null,
  modified_on: null,
  modified_by: null,
};

function wrap(node: ReactNode) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, retryDelay: 0 },
      mutations: { retry: false },
    },
  });
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{node}</ToastProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.previewScheduleTargets.mockResolvedValue({
    schedule_id: 7,
    scope: 'PROJECT',
    target_count: 1,
    skipped_count: 0,
    targets: [{
      project_id: 3,
      project_name: 'Medical Platform',
      product_id: 22,
      product_name: 'Controller',
      sbom_id: 81,
      sbom_name: 'controller.cdx',
      sbom_version: '2.0',
      effective_schedule_id: 7,
      effective_scope: 'PROJECT',
      included: true,
      resolution: 'PROJECT_INHERITED',
    }],
  });
  api.excludeFromParentSchedule.mockResolvedValue({});
  api.restoreScheduleInheritance.mockResolvedValue({});
  api.runScheduleNow.mockResolvedValue({ status: 'enqueued', schedule_id: 7, sbom_ids: [81], failed_sbom_ids: [] });
});

describe('ScheduleCard Product hierarchy', () => {
  it('renders the loading state while effective resolution is pending', () => {
    api.getEffectiveProductSchedule.mockReturnValue(new Promise(() => undefined));
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('renders an actionable load error', async () => {
    api.getEffectiveProductSchedule.mockRejectedValue(new Error('resolver unavailable'));
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    expect(await screen.findByText(/could not load schedule: resolver unavailable/i)).toBeInTheDocument();
  });

  it('opens Product schedule setup when no own or inherited schedule exists', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: null,
      state: 'NONE',
      source_scope: null,
      resolution_reason: 'NO_SCHEDULE',
      included: false,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    fireEvent.click(await screen.findByRole('button', { name: /set up schedule/i }));
    expect(screen.getByTestId('schedule-editor')).toHaveAttribute('data-existing-id', 'new');
  });

  it('renders inherited Product state, current target preview, and exclusion action', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: true,
      schedule,
      state: 'INHERITED',
      source_scope: 'PROJECT',
      resolution_reason: 'PROJECT_INHERITED',
      included: true,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    expect(await screen.findAllByText(/inherited from project/i)).not.toHaveLength(0);
    expect(await screen.findByText(/controller\.cdx 2\.0/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /exclude/i }));
    await waitFor(() => expect(api.excludeFromParentSchedule).toHaveBeenCalledWith('PRODUCT', 22));
  });

  it('renders an excluded Product with restore inheritance', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: { ...schedule, id: 9, scope: 'PRODUCT', project_id: null, product_id: 22, mode: 'EXCLUDED', enabled: false, state: 'EXCLUDED' },
      state: 'EXCLUDED',
      source_scope: 'PRODUCT',
      resolution_reason: 'EXCLUDED',
      included: false,
    });
    api.previewScheduleTargets.mockResolvedValue({ schedule_id: 9, scope: 'PRODUCT', target_count: 0, skipped_count: 1, targets: [] });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    const restore = await screen.findByRole('button', { name: /restore inheritance/i });
    fireEvent.click(restore);
    await waitFor(() => expect(api.restoreScheduleInheritance).toHaveBeenCalledWith('PRODUCT', 22));
  });

  it('runs a custom Product schedule using the shared Run Now API', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: { ...schedule, scope: 'PRODUCT', project_id: null, product_id: 22 },
      state: 'CUSTOM',
      source_scope: 'PRODUCT',
      resolution_reason: 'PRODUCT_OVERRIDE',
      included: true,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));
    fireEvent.click(await screen.findByRole('button', { name: /run now/i }));
    await waitFor(() => expect(api.runScheduleNow).toHaveBeenCalledWith(7));
  });

  it('edits and pauses a custom Product override', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: { ...schedule, scope: 'PRODUCT', project_id: null, product_id: 22 },
      state: 'CUSTOM',
      source_scope: 'PRODUCT',
      resolution_reason: 'PRODUCT_OVERRIDE',
      included: true,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    fireEvent.click(await screen.findByRole('button', { name: /edit/i }));
    expect(screen.getByTestId('schedule-editor')).toHaveAttribute('data-existing-id', '7');
    fireEvent.click(screen.getByRole('button', { name: /pause/i }));
    await waitFor(() => expect(api.pauseSchedule).toHaveBeenCalledWith(7));
  });

  it('resumes a paused Product override', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: { ...schedule, scope: 'PRODUCT', project_id: null, product_id: 22, enabled: false, state: 'PAUSED' },
      state: 'PAUSED',
      source_scope: 'PRODUCT',
      resolution_reason: 'PRODUCT_PAUSED',
      included: false,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    fireEvent.click(await screen.findByRole('button', { name: /resume/i }));
    await waitFor(() => expect(api.resumeSchedule).toHaveBeenCalledWith(7));
  });

  it('removes a Product override through the Product delete API', async () => {
    api.getEffectiveProductSchedule.mockResolvedValue({
      inherited: false,
      schedule: { ...schedule, scope: 'PRODUCT', project_id: null, product_id: 22 },
      state: 'CUSTOM',
      source_scope: 'PRODUCT',
      resolution_reason: 'PRODUCT_OVERRIDE',
      included: true,
    });
    render(wrap(<ScheduleCard scope="PRODUCT" targetId={22} />));

    fireEvent.click(await screen.findByRole('button', { name: /remove override/i }));
    fireEvent.click(await screen.findByRole('button', { name: /soft delete/i }));
    await waitFor(() => expect(api.deleteProductSchedule).toHaveBeenCalledWith(22, { permanent: false }));
  });
});

describe('ScheduleCard hierarchy sources and previews', () => {
  it('shows the Project target preview resolved by the backend', async () => {
    api.getProjectSchedule.mockResolvedValue(schedule);
    render(wrap(<ScheduleCard scope="PROJECT" targetId={3} />));

    expect(await screen.findByText(/controller\.cdx 2\.0/i)).toBeInTheDocument();
    expect(screen.getByText(/current sbom only/i)).toBeInTheDocument();
  });

  it('shows an exact SBOM inheriting its effective Product schedule', async () => {
    const productSchedule = {
      ...schedule,
      scope: 'PRODUCT' as const,
      project_id: null,
      product_id: 22,
    };
    api.getSbomSchedule.mockResolvedValue({
      inherited: true,
      schedule: productSchedule,
      state: 'INHERITED',
      source_scope: 'PRODUCT',
      resolution_reason: 'PRODUCT_OVERRIDE',
      included: true,
    });
    api.previewScheduleTargets.mockResolvedValue({
      schedule_id: 7,
      scope: 'PRODUCT',
      target_count: 1,
      skipped_count: 0,
      targets: [{
        project_id: 3,
        project_name: 'Medical Platform',
        product_id: 22,
        product_name: 'Controller',
        sbom_id: 81,
        sbom_name: 'controller.cdx',
        sbom_version: '2.0',
        effective_schedule_id: 7,
        effective_scope: 'PRODUCT',
        included: true,
        resolution: 'PRODUCT_OVERRIDE',
      }],
    });
    render(wrap(<ScheduleCard scope="SBOM" targetId={81} />));

    expect(await screen.findAllByText(/inherited from product/i)).not.toHaveLength(0);
    expect(await screen.findByText(/controller\.cdx 2\.0/i)).toBeInTheDocument();
  });
});
