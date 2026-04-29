'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Input } from '@/components/ui/Input';
import {
  upsertProjectSchedule,
  upsertSbomSchedule,
} from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import type {
  AnalysisSchedule,
  ScheduleCadence,
  ScheduleUpsertPayload,
} from '@/types';

/**
 * The friendly schedule editor: cadence preset chips + day/hour pickers.
 *
 * Targets either a project (scope='PROJECT') or a single SBOM
 * (scope='SBOM'). When editing an existing schedule, the form pre-fills
 * from the row; otherwise it shows the most common defaults
 * (Weekly, Monday, 02:00 UTC).
 *
 * "Custom (cron)" is hidden under an Advanced disclosure — it's a
 * power-user surface and most users should never see it.
 */

interface ScheduleEditorProps {
  open: boolean;
  onClose: () => void;
  scope: 'PROJECT' | 'SBOM';
  targetId: number;          // project_id or sbom_id depending on scope
  existing?: AnalysisSchedule | null;
}

const CADENCE_PRESETS: { value: ScheduleCadence; label: string; hint: string }[] = [
  { value: 'DAILY', label: 'Daily', hint: 'Every day' },
  { value: 'WEEKLY', label: 'Weekly', hint: 'Same weekday each week' },
  { value: 'BIWEEKLY', label: 'Bi-weekly', hint: 'Every 14 days' },
  { value: 'MONTHLY', label: 'Monthly', hint: 'Same date each month' },
  { value: 'QUARTERLY', label: 'Quarterly', hint: 'Every 3 months' },
];

const WEEKDAYS = [
  { value: 0, label: 'Monday' },
  { value: 1, label: 'Tuesday' },
  { value: 2, label: 'Wednesday' },
  { value: 3, label: 'Thursday' },
  { value: 4, label: 'Friday' },
  { value: 5, label: 'Saturday' },
  { value: 6, label: 'Sunday' },
];

interface FormState {
  cadence: ScheduleCadence;
  dayOfWeek: number;
  dayOfMonth: number;
  hourUtc: number;
  cronExpression: string;
  enabled: boolean;
  showAdvanced: boolean;
}

const defaultsFromExisting = (existing?: AnalysisSchedule | null): FormState => ({
  cadence: existing?.cadence ?? 'WEEKLY',
  dayOfWeek: existing?.day_of_week ?? 0,
  dayOfMonth: existing?.day_of_month ?? 1,
  hourUtc: existing?.hour_utc ?? 2,
  cronExpression: existing?.cron_expression ?? '',
  enabled: existing?.enabled ?? true,
  showAdvanced: existing?.cadence === 'CUSTOM',
});

export function ScheduleEditor({
  open,
  onClose,
  scope,
  targetId,
  existing,
}: ScheduleEditorProps) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [form, setForm] = useState<FormState>(() => defaultsFromExisting(existing));

  useEffect(() => {
    if (open) setForm(defaultsFromExisting(existing));
  }, [open, existing]);

  const showWeekdayField = form.cadence === 'WEEKLY' || form.cadence === 'BIWEEKLY';
  const showMonthDayField = form.cadence === 'MONTHLY' || form.cadence === 'QUARTERLY';
  const showCronField = form.cadence === 'CUSTOM';

  const payload = useMemo<ScheduleUpsertPayload>(() => {
    const p: ScheduleUpsertPayload = {
      cadence: form.cadence,
      hour_utc: form.hourUtc,
      enabled: form.enabled,
    };
    if (showWeekdayField) p.day_of_week = form.dayOfWeek;
    if (showMonthDayField) p.day_of_month = form.dayOfMonth;
    if (showCronField) p.cron_expression = form.cronExpression.trim();
    return p;
  }, [form, showWeekdayField, showMonthDayField, showCronField]);

  const mutation = useMutation({
    mutationFn: () =>
      scope === 'PROJECT'
        ? upsertProjectSchedule(targetId, payload)
        : upsertSbomSchedule(targetId, payload),
    onSuccess: () => {
      // Invalidate both project + sbom schedule queries; cheaper than
      // computing the precise key for every dependent panel.
      queryClient.invalidateQueries({ queryKey: ['schedule'] });
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      showToast(existing ? 'Schedule updated' : 'Schedule created', 'success');
      onClose();
    },
    onError: (err: Error) => {
      showToast(`Save failed: ${err.message}`, 'error');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={existing ? 'Edit schedule' : 'Create schedule'}
      maxWidth="lg"
    >
      <form onSubmit={handleSubmit}>
        <DialogBody className="space-y-5">
          {/* Cadence preset chips */}
          <div>
            <label className="block text-xs font-medium uppercase tracking-wide text-hcl-muted mb-2">
              How often?
            </label>
            <div className="flex flex-wrap gap-2">
              {CADENCE_PRESETS.map((preset) => {
                const selected = form.cadence === preset.value;
                return (
                  <button
                    key={preset.value}
                    type="button"
                    onClick={() => setForm((s) => ({ ...s, cadence: preset.value }))}
                    title={preset.hint}
                    className={`px-3 py-1.5 rounded-full text-sm border transition-colors ${
                      selected
                        ? 'bg-hcl-blue text-white border-hcl-blue'
                        : 'bg-surface text-hcl-navy border-hcl-border hover:border-hcl-blue'
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Day-of-week (WEEKLY/BIWEEKLY) */}
          {showWeekdayField && (
            <Select
              label="On which day?"
              value={String(form.dayOfWeek)}
              onChange={(e) =>
                setForm((s) => ({ ...s, dayOfWeek: Number(e.target.value) }))
              }
            >
              {WEEKDAYS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </Select>
          )}

          {/* Day-of-month (MONTHLY/QUARTERLY) */}
          {showMonthDayField && (
            <Input
              label="Day of month (1–28)"
              type="number"
              min={1}
              max={28}
              value={form.dayOfMonth}
              onChange={(e) =>
                setForm((s) => ({
                  ...s,
                  dayOfMonth: Math.max(1, Math.min(28, Number(e.target.value) || 1)),
                }))
              }
            />
          )}

          {/* Hour-of-day */}
          <div>
            <label className="block text-xs font-medium uppercase tracking-wide text-hcl-muted mb-2">
              At what hour (UTC)?
            </label>
            <Select
              value={String(form.hourUtc)}
              onChange={(e) =>
                setForm((s) => ({ ...s, hourUtc: Number(e.target.value) }))
              }
            >
              {Array.from({ length: 24 }).map((_, h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, '0')}:00 UTC
                </option>
              ))}
            </Select>
            <p className="mt-1 text-xs text-hcl-muted">
              Times are evaluated in UTC. Display in your local zone is up to your browser.
            </p>
          </div>

          {/* Enabled toggle */}
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm((s) => ({ ...s, enabled: e.target.checked }))}
              className="h-4 w-4 rounded border-hcl-border text-hcl-blue focus:ring-hcl-blue"
            />
            <span className="text-sm text-hcl-navy">Enabled</span>
          </label>

          {/* Advanced disclosure — cron */}
          <div className="border-t border-hcl-border pt-3">
            <button
              type="button"
              onClick={() =>
                setForm((s) => ({
                  ...s,
                  showAdvanced: !s.showAdvanced,
                  // collapsing advanced reverts a CUSTOM selection to WEEKLY
                  cadence:
                    !s.showAdvanced || s.cadence !== 'CUSTOM' ? s.cadence : 'WEEKLY',
                }))
              }
              className="text-xs font-medium text-hcl-muted hover:text-hcl-blue"
            >
              {form.showAdvanced ? '▾' : '▸'} Advanced (custom cron)
            </button>
            {form.showAdvanced && (
              <div className="mt-3 space-y-2">
                <button
                  type="button"
                  onClick={() => setForm((s) => ({ ...s, cadence: 'CUSTOM' }))}
                  className={`px-3 py-1.5 rounded-full text-sm border transition-colors ${
                    form.cadence === 'CUSTOM'
                      ? 'bg-hcl-blue text-white border-hcl-blue'
                      : 'bg-surface text-hcl-navy border-hcl-border hover:border-hcl-blue'
                  }`}
                >
                  Custom (cron)
                </button>
                {showCronField && (
                  <Input
                    label="Cron expression (5 fields, UTC)"
                    placeholder="0 2 * * 1"
                    value={form.cronExpression}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, cronExpression: e.target.value }))
                    }
                  />
                )}
              </div>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={mutation.isPending}>
            {existing ? 'Save changes' : 'Create schedule'}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
