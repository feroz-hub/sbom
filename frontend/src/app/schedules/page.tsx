'use client';

import { useCallback, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import {
  CalendarClock,
  Eye,
  Pause,
  Pencil,
  Play,
  Trash2,
  Zap,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Alert } from '@/components/ui/Alert';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import {
  Table,
  TableBody,
  TableHead,
  Th,
  Td,
  EmptyRow,
} from '@/components/ui/Table';
import { SkeletonRow } from '@/components/ui/Spinner';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { ScheduleEditor } from '@/components/schedules/ScheduleEditor';
import {
  deleteProjectSchedule,
  deleteSbomSchedule,
  deleteScopedSchedule,
  getProjects,
  getSboms,
  listSchedules,
  pauseSchedule,
  previewScheduleTargets,
  resumeSchedule,
  runScheduleNow,
} from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { getApiErrorMessage } from '@/lib/notifications';
import { formatRelative } from '@/lib/utils';
import { matchesMultiField } from '@/lib/tableFilters';
import { canonicalRunStatus } from '@/lib/analysisRunStatusLabels';
import {
  invalidateDashboardTiles,
  invalidateRunLists,
  invalidateSbomLists,
} from '@/lib/queryInvalidation';
import type { AnalysisSchedule, Project, SBOMSource } from '@/types';

type ScopeFilter = 'all' | 'TENANT' | 'PROJECT' | 'PRODUCT' | 'SBOM';
type EnabledFilter = 'all' | 'enabled' | 'paused';

const cadenceSummary = (s: AnalysisSchedule): string => {
  const hour = `${String(s.hour_utc).padStart(2, '0')}:00 UTC`;
  switch (s.cadence) {
    case 'DAILY':
      return `Daily · ${hour}`;
    case 'WEEKLY':
      return `Weekly · ${WEEKDAYS[s.day_of_week ?? 0]} · ${hour}`;
    case 'BIWEEKLY':
      return `Bi-weekly · ${WEEKDAYS[s.day_of_week ?? 0]} · ${hour}`;
    case 'MONTHLY':
      return `Monthly · day ${s.day_of_month ?? '?'} · ${hour}`;
    case 'QUARTERLY':
      return `Quarterly · day ${s.day_of_month ?? '?'} · ${hour}`;
    case 'CUSTOM':
      return `Cron: ${s.cron_expression ?? '—'}`;
  }
};

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

export default function SchedulesPage() {
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const [scope, setScope] = useState<ScopeFilter>('all');
  const [enabled, setEnabled] = useState<EnabledFilter>('all');
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<AnalysisSchedule | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AnalysisSchedule | null>(null);
  const [previewing, setPreviewing] = useState<AnalysisSchedule | null>(null);

  const schedulesQuery = useQuery({
    queryKey: ['schedules', { scope, enabled }],
    queryFn: ({ signal }) =>
      listSchedules(
        {
          scope: scope === 'all' ? undefined : scope,
          enabled: enabled === 'all' ? undefined : enabled === 'enabled',
        },
        signal,
      ),
  });

  // Pull projects & sboms once so we can render names instead of bare IDs.
  // Both are list endpoints already used elsewhere — no extra server work.
  const projectsQuery = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const sbomsQuery = useQuery({
    queryKey: ['sboms', 'for-schedules'],
    queryFn: ({ signal }) => getSboms(1, 500, signal),
  });

  const projectById = useMemo(
    () => new Map<number, Project>((projectsQuery.data ?? []).map((p) => [p.id, p])),
    [projectsQuery.data],
  );
  const sbomById = useMemo(
    () => new Map<number, SBOMSource>((sbomsQuery.data ?? []).map((s) => [s.id, s])),
    [sbomsQuery.data],
  );

  const targetLabel = useCallback((sched: AnalysisSchedule): string => {
    if (sched.scope === 'TENANT') return `Tenant #${sched.tenant_id ?? ''}`;
    if (sched.scope === 'PRODUCT') return sched.product_name ?? `Product #${sched.product_id ?? ''}`;
    if (sched.scope === 'PROJECT' && sched.project_id != null) {
      return sched.project_name ?? projectById.get(sched.project_id)?.project_name ?? `Project #${sched.project_id}`;
    }
    if (sched.scope === 'SBOM' && sched.sbom_id != null) {
      const name = sched.sbom_name ?? sbomById.get(sched.sbom_id)?.sbom_name ?? `SBOM #${sched.sbom_id}`;
      return `${name}${sched.sbom_version ? ` ${sched.sbom_version}` : ''}`;
    }
    return '—';
  }, [projectById, sbomById]);

  const filteredRows = useMemo(() => {
    const rows = schedulesQuery.data ?? [];
    if (!search.trim()) return rows;
    return rows.filter((s) =>
      matchesMultiField(search, [
        targetLabel(s),
        s.scope,
        s.cadence,
        cadenceSummary(s),
        s.last_run_status,
      ]),
    );
  }, [schedulesQuery.data, search, targetLabel]);

  // Mutations — share the same invalidator since the schedules list is the
  // canonical source for this page; the per-target schedule queries (used
  // by the project/SBOM cards) are also keyed under "schedule" so they
  // refresh together.
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['schedules'] });
    queryClient.invalidateQueries({ queryKey: ['schedule'] });
  };

  const pauseM = useMutation({
    mutationFn: (id: number) => pauseSchedule(id),
    onSuccess: () => {
      showToast('Paused', 'success');
      invalidate();
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Schedule pause failed.'), 'error'),
  });
  const resumeM = useMutation({
    mutationFn: (id: number) => resumeSchedule(id),
    onSuccess: () => {
      showToast('Resumed', 'success');
      invalidate();
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Schedule resume failed.'), 'error'),
  });
  const runNowM = useMutation({
    mutationFn: (id: number) => runScheduleNow(id),
    onSuccess: (res) => {
      showToast(
        `Enqueued ${res.sbom_ids.length} SBOM analysis${res.sbom_ids.length === 1 ? '' : 'es'}`,
        'success',
      );
      // Enqueuing creates new runs and flips affected SBOMs into RUNNING —
      // refresh runs list, SBOM analysis badges, and dashboard counts so
      // every surface reflects the in-flight work.
      invalidateRunLists(queryClient);
      invalidateSbomLists(queryClient);
      invalidateDashboardTiles(queryClient);
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'The scheduled analysis could not be queued.'), 'error'),
  });
  const deleteM = useMutation({
    mutationFn: ({
      sched,
      permanent,
    }: {
      sched: AnalysisSchedule;
      permanent: boolean;
    }) =>
      sched.scope === 'TENANT' && sched.tenant_id != null ? deleteScopedSchedule('TENANT', sched.tenant_id)
        : sched.scope === 'PRODUCT' && sched.product_id != null ? deleteScopedSchedule('PRODUCT', sched.product_id)
        : sched.scope === 'PROJECT' && sched.project_id != null
        ? deleteProjectSchedule(sched.project_id, { permanent })
        : sched.scope === 'SBOM' && sched.sbom_id != null
          ? deleteSbomSchedule(sched.sbom_id, { permanent })
          : Promise.reject(new Error('Schedule has no resolvable target')),
    onSuccess: (_data, { permanent }) => {
      showToast(
        permanent ? 'Schedule permanently removed' : 'Schedule removed',
        'success',
      );
      setConfirmDelete(null);
      invalidate();
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Schedule deletion failed.'), 'error'),
  });

  const previewQuery = useQuery({
    queryKey: ['schedule-targets', previewing?.id],
    queryFn: ({ signal }) => previewScheduleTargets(previewing!.id, signal),
    enabled: previewing != null,
  });

  const filtersActive = scope !== 'all' || enabled !== 'all' || search.trim() !== '';
  const total = schedulesQuery.data?.length ?? 0;
  const shown = filteredRows.length;

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Schedules"
        subtitle="Periodic analysis configuration across projects, products, and SBOMs"
      />
      <div className="p-6 space-y-4">
        {schedulesQuery.error ? (
          <Alert variant="error" title="Could not load schedules">
            {(schedulesQuery.error as Error).message}
          </Alert>
        ) : null}

        <Card>
          <TableFilterBar
            onClear={() => {
              setSearch('');
              setScope('all');
              setEnabled('all');
            }}
            clearDisabled={!filtersActive}
            resultHint={
              filtersActive
                ? `Showing ${shown} of ${total}`
                : `${total} schedule${total === 1 ? '' : 's'}`
            }
          >
            <TableSearchInput
              value={search}
              onChange={setSearch}
              placeholder="Project, SBOM, cadence…"
              label="Search"
            />
            <div className="w-full min-w-[10rem] sm:w-44">
              <Select
                label="Scope"
                value={scope}
                onChange={(e) => setScope(e.target.value as ScopeFilter)}
                className="w-full"
              >
                <option value="all">All scopes</option>
                <option value="PROJECT">Project</option>
                <option value="TENANT">Tenant</option>
                <option value="PRODUCT">Product</option>
                <option value="SBOM">SBOM</option>
              </Select>
            </div>
            <div className="w-full min-w-[10rem] sm:w-44">
              <Select
                label="State"
                value={enabled}
                onChange={(e) => setEnabled(e.target.value as EnabledFilter)}
                className="w-full"
              >
                <option value="all">All</option>
                <option value="enabled">Enabled only</option>
                <option value="paused">Paused only</option>
              </Select>
            </div>
          </TableFilterBar>

          <Table striped ariaLabel="All schedules">
            <TableHead>
              <tr>
                <Th>Scope</Th>
                <Th>Target</Th>
                <Th>Cadence</Th>
                <Th>Target policy</Th>
                <Th>Next run</Th>
                <Th>Last run</Th>
                <Th>State</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </TableHead>
            <TableBody>
              {schedulesQuery.isLoading ? (
                Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cols={8} />)
              ) : !shown ? (
                <EmptyRow
                  cols={8}
                  message={
                    filtersActive
                      ? 'No schedules match your filters.'
                      : 'No schedules yet. Configure one from a project, product, or SBOM page.'
                  }
                />
              ) : (
                filteredRows.map((s) => (
                  <tr key={s.id} className="hover:bg-hcl-light/40">
                    <Td>
                      <Badge variant={s.scope === 'PROJECT' ? 'info' : 'gray'}>
                        {s.scope}
                      </Badge>
                    </Td>
                    <Td className="font-medium text-hcl-navy">
                      {s.scope === 'PROJECT' && s.project_id != null ? (
                        <Link href={`/projects`} className="hover:underline">
                          {targetLabel(s)}
                        </Link>
                      ) : s.scope === 'PRODUCT' && s.product_id != null ? (
                        <Link href={`/products/${s.product_id}`} className="hover:underline">
                          {targetLabel(s)}
                        </Link>
                      ) : s.scope === 'SBOM' && s.sbom_id != null ? (
                        <Link href={`/sboms/${s.sbom_id}`} className="hover:underline">
                          {targetLabel(s)}
                        </Link>
                      ) : (
                        targetLabel(s)
                      )}
                    </Td>
                    <Td className="text-sm text-hcl-navy">{cadenceSummary(s)}</Td>
                    <Td className="text-sm text-hcl-navy">
                      {s.scope === 'SBOM'
                        ? 'Exact SBOM'
                        : s.target_version_policy === 'ALL_ACTIVE_VERSIONS'
                          ? 'All active versions'
                          : 'Current only'}
                    </Td>
                    <Td className="text-sm">
                      {s.enabled && s.next_run_at ? (
                        <span title={s.next_run_at}>{formatRelative(s.next_run_at)}</span>
                      ) : (
                        <span className="text-hcl-muted">paused</span>
                      )}
                    </Td>
                    <Td className="text-sm">
                      {s.last_run_at ? (
                        <span title={s.last_run_at}>
                          {formatRelative(s.last_run_at)}
                          {s.last_run_status && (() => {
                            // ADR-0001: backend emits OK/FINDINGS — never PASS/FAIL.
                            // Audit §I1.2-F8: hard-coded legacy strings here painted
                            // every successful run with the muted-grey "other" style.
                            const canonical = canonicalRunStatus(s.last_run_status);
                            const cls =
                              canonical === 'OK'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : canonical === 'FINDINGS'
                                  ? 'bg-red-50 text-red-700 border-red-200'
                                  : canonical === 'ERROR'
                                    ? 'bg-orange-50 text-orange-700 border-orange-200'
                                    : 'bg-hcl-light text-hcl-muted border-hcl-border';
                            return (
                              <span
                                className={`ml-2 inline-flex items-center px-1.5 py-0 rounded text-[10px] font-bold border ${cls}`}
                              >
                                {s.last_run_status}
                              </span>
                            );
                          })()}
                        </span>
                      ) : (
                        <span className="text-hcl-muted">never</span>
                      )}
                    </Td>
                    <Td>
                      <Badge variant={s.state === 'CUSTOM' ? 'success' : 'gray'}>
                        {s.state === 'EXCLUDED' ? 'Excluded' : s.enabled ? 'Enabled' : 'Paused'}
                      </Badge>
                      {s.consecutive_failures > 0 && (
                        <span
                          className="ml-2 text-[10px] font-medium text-orange-700"
                          title={`Backoff is in effect after ${s.consecutive_failures} consecutive failure${s.consecutive_failures === 1 ? '' : 's'}.`}
                        >
                          ⚠ {s.consecutive_failures} fail
                        </span>
                      )}
                    </Td>
                    <Td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => setPreviewing(s)}
                        >
                          <Eye className="h-4 w-4" />
                          Preview
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={s.state === 'EXCLUDED'}
                          loading={runNowM.isPending && runNowM.variables === s.id}
                          onClick={() => runNowM.mutate(s.id)}
                        >
                          <Zap className="h-4 w-4" />
                          Run now
                        </Button>
                        {s.state === 'EXCLUDED' ? null : s.enabled ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            loading={pauseM.isPending && pauseM.variables === s.id}
                            onClick={() => pauseM.mutate(s.id)}
                          >
                            <Pause className="h-4 w-4" />
                            Pause
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="secondary"
                            loading={resumeM.isPending && resumeM.variables === s.id}
                            onClick={() => resumeM.mutate(s.id)}
                          >
                            <Play className="h-4 w-4" />
                            Resume
                          </Button>
                        )}
                        <button
                          onClick={() => setEditing(s)}
                          aria-label="Edit"
                          className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-blue"
                        >
                          <Pencil className="h-4 w-4" />
                          Edit
                        </button>
                        <button
                          onClick={() => setConfirmDelete(s)}
                          aria-label="Remove"
                          className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40"
                        >
                          <Trash2 className="h-4 w-4" />
                          Remove
                        </button>
                      </div>
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {previewing && (
          <Card>
            <div className="flex items-center justify-between border-b border-hcl-border p-4">
              <div>
                <h2 className="font-semibold text-hcl-navy">Target preview — {targetLabel(previewing)}</h2>
                <p className="text-sm text-hcl-muted">
                  The same resolver is used by Run Now and Celery Beat.
                </p>
              </div>
              <Button size="sm" variant="secondary" onClick={() => setPreviewing(null)}>Close</Button>
            </div>
            <div className="p-4">
              {previewQuery.isLoading ? (
                <p className="text-sm text-hcl-muted">Resolving targets…</p>
              ) : previewQuery.error ? (
                <Alert variant="error" title="Could not preview targets">
                  {(previewQuery.error as Error).message}
                </Alert>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-hcl-navy">
                    {previewQuery.data?.target_count ?? 0} included · {previewQuery.data?.skipped_count ?? 0} skipped
                  </p>
                  <div className="max-h-80 space-y-1 overflow-auto">
                    {(previewQuery.data?.targets ?? []).map((target, index) => (
                      <div
                        key={`${target.sbom_id ?? 'product'}-${index}`}
                        className="flex items-center justify-between rounded border border-hcl-border px-3 py-2 text-sm"
                      >
                        <span className={target.included ? 'text-hcl-navy' : 'text-hcl-muted'}>
                          {target.project_name ?? 'Project'} / {target.product_name ?? 'Product'} /{' '}
                          {target.sbom_name ?? 'No current SBOM'}{target.sbom_version ? ` ${target.sbom_version}` : ''}
                        </span>
                        <Badge variant={target.included ? 'success' : 'gray'}>
                          {target.resolution.replaceAll('_', ' ').toLowerCase()}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Helper text — explains where new schedules come from. */}
        <div className="text-xs text-hcl-muted flex items-center gap-2">
          <CalendarClock className="h-3.5 w-3.5" />
          Schedules are created from project, product, or SBOM pages. More-specific rows override parent schedules.
        </div>
      </div>

      {editing && (
        <ScheduleEditor
          open={!!editing}
          onClose={() => setEditing(null)}
          scope={editing.scope}
          targetId={(editing.scope === 'TENANT' ? editing.tenant_id : editing.scope === 'PRODUCT' ? editing.product_id : editing.scope === 'PROJECT' ? editing.project_id : editing.sbom_id) ?? 0}
          existing={editing}
        />
      )}

      <DeleteConfirmDialog
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={({ permanent }) =>
          confirmDelete && deleteM.mutate({ sched: confirmDelete, permanent })
        }
        loading={deleteM.isPending}
        recordName={confirmDelete ? cadenceSummary(confirmDelete) : ''}
        recordKind={
          confirmDelete?.scope === 'PROJECT'
            ? 'project schedule'
            : confirmDelete?.scope === 'PRODUCT'
              ? 'product schedule override'
              : confirmDelete?.scope === 'TENANT'
                ? 'tenant schedule'
                : 'SBOM schedule override'
        }
        title={
          confirmDelete?.scope === 'PROJECT'
            ? 'Remove project schedule?'
            : confirmDelete?.scope === 'PRODUCT'
              ? 'Remove product override?'
              : confirmDelete?.scope === 'TENANT'
                ? 'Remove tenant schedule?'
                : 'Remove SBOM override?'
        }
        cascadeImpact={[]}
      />
    </div>
  );
}
