'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, Pause, Pencil, Play, Trash2, Zap } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ConfirmDialog } from '@/components/ui/Dialog';
import {
  deleteProjectSchedule,
  deleteSbomSchedule,
  getProjectSchedule,
  getSbomSchedule,
  pauseSchedule,
  resumeSchedule,
  runScheduleNow,
} from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { formatRelative } from '@/lib/utils';
import { HttpError } from '@/lib/api';
import { ScheduleEditor } from './ScheduleEditor';
import type { AnalysisSchedule, ScheduleCadence } from '@/types';

/**
 * Schedule summary card slotted into project / SBOM detail surfaces.
 *
 * - Project scope: GET /api/projects/{id}/schedule. 404 = no schedule.
 * - SBOM scope: GET /api/sboms/{id}/schedule returns inherited + schedule;
 *   so the card can show "Inherits from project: weekly Monday 02:00"
 *   with an "Override" CTA, or the SBOM's own override with "Remove
 *   override" semantics.
 */

interface ScheduleCardProps {
  scope: 'PROJECT' | 'SBOM';
  targetId: number;
}

const cadenceLabel = (s: AnalysisSchedule): string => {
  const hour = `${String(s.hour_utc).padStart(2, '0')}:00 UTC`;
  switch (s.cadence) {
    case 'DAILY':
      return `Daily at ${hour}`;
    case 'WEEKLY': {
      const day = WEEKDAYS[s.day_of_week ?? 0] ?? '?';
      return `Weekly on ${day} at ${hour}`;
    }
    case 'BIWEEKLY': {
      const day = WEEKDAYS[s.day_of_week ?? 0] ?? '?';
      return `Bi-weekly on ${day} at ${hour}`;
    }
    case 'MONTHLY':
      return `Monthly on day ${s.day_of_month ?? '?'} at ${hour}`;
    case 'QUARTERLY':
      return `Quarterly on day ${s.day_of_month ?? '?'} at ${hour}`;
    case 'CUSTOM':
      return `Custom: ${s.cron_expression ?? '—'}`;
  }
};

const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

const CADENCE_BADGE: Record<ScheduleCadence, string> = {
  DAILY: 'bg-blue-50 text-blue-700 border-blue-200',
  WEEKLY: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  BIWEEKLY: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  MONTHLY: 'bg-amber-50 text-amber-700 border-amber-200',
  QUARTERLY: 'bg-amber-50 text-amber-700 border-amber-200',
  CUSTOM: 'bg-purple-50 text-purple-700 border-purple-200',
};

export function ScheduleCard({ scope, targetId }: ScheduleCardProps) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [showEditor, setShowEditor] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const queryKey = ['schedule', scope, targetId];

  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      scope === 'PROJECT'
        ? getProjectSchedule(targetId, signal).then((s) => ({ inherited: false, schedule: s }))
        : getSbomSchedule(targetId, signal),
    // 404 from GET /api/projects/{id}/schedule means "no schedule" — render
    // the empty state instead of an error toast. Other errors still surface.
    retry: (failureCount, err) =>
      err instanceof HttpError && err.status === 404 ? false : failureCount < 2,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['schedule'] });

  const pauseMutation = useMutation({
    mutationFn: (id: number) => pauseSchedule(id),
    onSuccess: () => {
      showToast('Schedule paused', 'success');
      invalidate();
    },
    onError: (err: Error) => showToast(`Pause failed: ${err.message}`, 'error'),
  });

  const resumeMutation = useMutation({
    mutationFn: (id: number) => resumeSchedule(id),
    onSuccess: () => {
      showToast('Schedule resumed', 'success');
      invalidate();
    },
    onError: (err: Error) => showToast(`Resume failed: ${err.message}`, 'error'),
  });

  const runNowMutation = useMutation({
    mutationFn: (id: number) => runScheduleNow(id),
    onSuccess: (res) => {
      showToast(
        `Enqueued ${res.sbom_ids.length} SBOM analysis${res.sbom_ids.length === 1 ? '' : 'es'}`,
        'success',
      );
    },
    onError: (err: Error) => showToast(`Run-now failed: ${err.message}`, 'error'),
  });

  const deleteMutation = useMutation({
    mutationFn: () =>
      scope === 'PROJECT'
        ? deleteProjectSchedule(targetId)
        : deleteSbomSchedule(targetId),
    onSuccess: () => {
      showToast(scope === 'PROJECT' ? 'Schedule removed' : 'Override removed', 'success');
      setConfirmDelete(false);
      invalidate();
    },
    onError: (err: Error) => showToast(`Remove failed: ${err.message}`, 'error'),
  });

  // Empty state — no project schedule, or no SBOM override AND no parent cascade.
  const noScheduleAtAll =
    !query.isLoading &&
    !query.error &&
    (!query.data?.schedule || (scope === 'PROJECT' && query.data.schedule === null));

  if (query.isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4" /> Periodic analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-hcl-muted">Loading…</p>
        </CardContent>
      </Card>
    );
  }

  if (query.error && !(query.error instanceof HttpError && query.error.status === 404)) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4" /> Periodic analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-red-600">Could not load schedule: {query.error.message}</p>
        </CardContent>
      </Card>
    );
  }

  // Project: 404 / no row → empty state. SBOM: schedule===null → empty state.
  const is404 = query.error instanceof HttpError && query.error.status === 404;
  if (is404 || noScheduleAtAll) {
    return (
      <>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4" /> Periodic analysis
            </CardTitle>
            <Button size="sm" onClick={() => setShowEditor(true)}>
              <Pencil className="h-4 w-4" /> Set up schedule
            </Button>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-hcl-muted">
              {scope === 'PROJECT'
                ? 'No schedule. SBOMs in this project are only analyzed on manual runs.'
                : 'No schedule (own or inherited). This SBOM is only analyzed on manual runs.'}
            </p>
          </CardContent>
        </Card>
        <ScheduleEditor
          open={showEditor}
          onClose={() => setShowEditor(false)}
          scope={scope}
          targetId={targetId}
        />
      </>
    );
  }

  const sched = query.data!.schedule!;
  const inherited = scope === 'SBOM' && (query.data!.inherited === true);

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex flex-wrap items-center gap-2">
            <CalendarClock className="h-4 w-4" />
            <span>Periodic analysis</span>
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ${CADENCE_BADGE[sched.cadence]}`}
            >
              {sched.cadence.toLowerCase()}
            </span>
            {inherited && (
              <span title="Following the project's cascade. Click Override to set a per-SBOM schedule.">
                <Badge variant="gray">inherited from project</Badge>
              </span>
            )}
            {!sched.enabled && <Badge variant="gray">paused</Badge>}
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="secondary" onClick={() => setShowEditor(true)}>
              <Pencil className="h-4 w-4" />
              {inherited ? 'Override' : 'Edit'}
            </Button>
            {!inherited && (
              <>
                {sched.enabled ? (
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={pauseMutation.isPending}
                    onClick={() => pauseMutation.mutate(sched.id)}
                  >
                    <Pause className="h-4 w-4" /> Pause
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={resumeMutation.isPending}
                    onClick={() => resumeMutation.mutate(sched.id)}
                  >
                    <Play className="h-4 w-4" /> Resume
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  loading={runNowMutation.isPending}
                  onClick={() => runNowMutation.mutate(sched.id)}
                  title="Trigger an analysis immediately. The cadence cursor is unchanged."
                >
                  <Zap className="h-4 w-4" /> Run now
                </Button>
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40"
                  aria-label={scope === 'PROJECT' ? 'Remove schedule' : 'Remove override'}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Field label="Cadence" value={cadenceLabel(sched)} />
            <Field
              label="Next run"
              value={
                sched.enabled && sched.next_run_at
                  ? `${formatRelative(sched.next_run_at)} · ${sched.next_run_at}`
                  : 'paused'
              }
            />
            <Field
              label="Last run"
              value={
                sched.last_run_at
                  ? `${formatRelative(sched.last_run_at)} · ${sched.last_run_status ?? '—'}`
                  : 'never'
              }
            />
            <Field
              label="Skip recent runs"
              value={`if a run completed in the last ${sched.min_gap_minutes} min`}
            />
          </dl>
        </CardContent>
      </Card>

      <ScheduleEditor
        open={showEditor}
        onClose={() => setShowEditor(false)}
        scope={scope}
        targetId={targetId}
        // For "inherited" SBOM cards, opening the editor creates a NEW
        // SBOM-level override — we do NOT pass the project's row as the
        // "existing" record, since editing it would mutate the project
        // schedule from inside the SBOM page (surprising).
        existing={inherited ? null : sched}
      />

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => deleteMutation.mutate()}
        title={scope === 'PROJECT' ? 'Remove schedule' : 'Remove SBOM override'}
        message={
          scope === 'PROJECT'
            ? 'SBOMs in this project will no longer be re-analyzed automatically.'
            : 'This SBOM will fall back to the project-level cascade (or stop being scheduled if there is none).'
        }
        confirmLabel="Remove"
        loading={deleteMutation.isPending}
      />
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">{label}</dt>
      <dd className="mt-1 text-sm font-medium text-hcl-navy break-words">{value}</dd>
    </div>
  );
}
