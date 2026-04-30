'use client';

import { Flame, Wrench } from 'lucide-react';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import { SeverityBadge } from '@/components/ui/Badge';
import type { CompareResult, FindingDiffRow } from '@/types/compare';

interface Props {
  result: CompareResult;
}

const SEVERITY_KEYS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
const SEVERITY_COLOURS: Record<(typeof SEVERITY_KEYS)[number], string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-amber-500',
  LOW: 'bg-blue-500',
  UNKNOWN: 'bg-slate-400',
};

function StackedBar({
  distribution,
  total,
}: {
  distribution: Record<string, number>;
  total: number;
}) {
  const max = Math.max(1, total);
  return (
    <div className="space-y-1">
      <div className="flex h-6 w-full overflow-hidden rounded-md bg-border-subtle">
        {SEVERITY_KEYS.map((key) => {
          const n = distribution[key] ?? 0;
          if (n === 0) return null;
          const pct = (n / max) * 100;
          return (
            <div
              key={key}
              className={SEVERITY_COLOURS[key]}
              style={{ width: `${pct}%` }}
              title={`${key}: ${n}`}
            />
          );
        })}
      </div>
      <ul className="flex flex-wrap gap-3 text-[11px] text-hcl-muted">
        {SEVERITY_KEYS.map((key) => {
          const n = distribution[key] ?? 0;
          if (n === 0) return null;
          return (
            <li key={key} className="inline-flex items-center gap-1">
              <span
                aria-hidden
                className={`h-2 w-2 rounded-full ${SEVERITY_COLOURS[key]}`}
              />
              {key}: <strong className="text-hcl-navy">{n}</strong>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function totalOf(distribution: Record<string, number>): number {
  return SEVERITY_KEYS.reduce((acc, key) => acc + (distribution[key] ?? 0), 0);
}

function ContributorList({
  rows,
  emptyMsg,
}: {
  rows: FindingDiffRow[];
  emptyMsg: string;
}) {
  if (rows.length === 0) {
    return <p className="text-xs text-hcl-muted">{emptyMsg}</p>;
  }
  return (
    <ol className="space-y-2">
      {rows.map((row, idx) => {
        const sev =
          row.change_kind === 'resolved'
            ? row.severity_a
            : row.severity_b ?? row.severity_a;
        const version =
          row.change_kind === 'resolved'
            ? row.component_version_a
            : row.component_version_b ?? row.component_version_a;
        return (
          <li
            key={`${row.vuln_id}|${idx}`}
            className="flex items-start gap-3 rounded-md border border-border-subtle bg-surface px-3 py-2"
          >
            <span className="font-metric mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-hcl-light text-[11px] font-bold text-hcl-blue">
              {idx + 1}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-xs text-hcl-navy">{row.vuln_id}</span>
                <SeverityBadge severity={(sev ?? 'unknown').toUpperCase()} />
                {row.kev_current && (
                  <span className="inline-flex items-center gap-0.5 rounded-full border border-red-300 bg-red-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-red-900">
                    <Flame className="h-2.5 w-2.5" aria-hidden />
                    KEV
                  </span>
                )}
                {row.fix_available && (
                  <span className="inline-flex items-center gap-0.5 rounded-full border border-emerald-300 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-emerald-900">
                    <Wrench className="h-2.5 w-2.5" aria-hidden />
                    FIX
                  </span>
                )}
              </div>
              <div className="mt-0.5 text-xs text-hcl-muted">
                <span className="text-hcl-navy">{row.component_name}</span>
                {version && <span> @ {version}</span>}
                {row.attribution && <span className="italic"> · {row.attribution}</span>}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/**
 * Tab 3 — Posture detail (ADR-0008 §5).
 * Read-only analytical view; deliberately no row interactions.
 *
 * Top-5 lists use the display-only ordinal rank from the backend
 * (KEV first → severity → fix-available → alphabetical). NO weighted
 * scalar score (PB-1).
 */
export function PostureDetailTab({ result }: Props) {
  const totalA = totalOf(result.posture.severity_distribution_a);
  const totalB = totalOf(result.posture.severity_distribution_b);

  return (
    <div className="space-y-4">
      <Surface variant="elevated">
        <SurfaceContent className="space-y-4">
          <h3 className="text-sm font-semibold text-hcl-navy">
            Severity composition
          </h3>
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
                Run A · {totalA} findings
              </div>
              <StackedBar
                distribution={result.posture.severity_distribution_a}
                total={Math.max(totalA, totalB)}
              />
            </div>
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
                Run B · {totalB} findings
              </div>
              <StackedBar
                distribution={result.posture.severity_distribution_b}
                total={Math.max(totalA, totalB)}
              />
            </div>
          </div>
        </SurfaceContent>
      </Surface>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Surface variant="elevated">
          <SurfaceContent className="space-y-3">
            <div>
              <h3 className="text-sm font-semibold text-emerald-700 dark:text-emerald-300">
                Top risk reductions
              </h3>
              <p className="text-[11px] text-hcl-muted">
                Ranked: KEV first, then severity, then fix-available, then id.
              </p>
            </div>
            <ContributorList
              rows={result.posture.top_resolutions}
              emptyMsg="No findings resolved between these runs."
            />
          </SurfaceContent>
        </Surface>

        <Surface variant="elevated">
          <SurfaceContent className="space-y-3">
            <div>
              <h3 className="text-sm font-semibold text-red-700 dark:text-red-300">
                Top risk introductions
              </h3>
              <p className="text-[11px] text-hcl-muted">
                Same ranking. Findings introduced by Run B.
              </p>
            </div>
            <ContributorList
              rows={result.posture.top_regressions}
              emptyMsg="No new findings introduced by Run B."
            />
          </SurfaceContent>
        </Surface>
      </div>
    </div>
  );
}
