'use client';

import { Flame, Wrench, Zap } from 'lucide-react';
import { SeverityBadge } from '@/components/ui/Badge';
import { cn } from '@/lib/utils';
import type { CveSeverity } from '@/types/cve';
import type { FindingDiffRow } from '@/types/compare';
import { FindingChangeKindChip } from '../FindingsTab/ChangeKindChip';
import { AttributionLine } from './AttributionLine';
import { CveHoverCard } from './CveHoverCard';
import { SeverityGradient } from './SeverityGradient';

interface Props {
  row: FindingDiffRow;
  onOpen: () => void;
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  none: 'NONE',
  unknown: 'UNKNOWN',
};

function severityLabel(s: CveSeverity | null | undefined): string {
  return s ? (SEVERITY_LABEL[s] ?? 'UNKNOWN') : 'UNKNOWN';
}

function pickVisibleSeverity(row: FindingDiffRow): CveSeverity {
  if (row.change_kind === 'resolved') return row.severity_a ?? 'unknown';
  return row.severity_b ?? row.severity_a ?? 'unknown';
}

function versionDisplay(row: FindingDiffRow): string {
  if (row.change_kind === 'resolved') return row.component_version_a ?? '—';
  if (row.change_kind === 'added') return row.component_version_b ?? '—';
  if (row.component_version_a === row.component_version_b) {
    return row.component_version_b ?? '—';
  }
  return `${row.component_version_a ?? '—'} → ${row.component_version_b ?? '—'}`;
}

/**
 * The advanced findings row.
 *
 * Two visual axes:
 *   1. change_kind — 4px solid border-l (red/green/amber/slate)
 *   2. severity   — 60px linear-gradient fade tinted by severity colour
 *
 * Together they communicate "this is a NEW (border) CRITICAL (gradient)
 * finding" at a glance.
 *
 * Row body adds (vs v1):
 *   - EPSS chip when percentile >= 50
 *   - Hover card on CVE id (cache-only; no fetch on hover)
 *   - Italic attribution second line with version-arrow tone
 *
 * Row height grows from 52px → 72px when attribution is present. Rows
 * without attribution stay 52px.
 */
export function FindingRowAdvanced({ row, onOpen }: Props) {
  const visibleSev = pickVisibleSeverity(row);
  const epssPct = row.epss_percentile_current;
  const showEpss = typeof epssPct === 'number' && epssPct >= 0.5;
  const epssLabel = showEpss ? `${Math.round((epssPct as number) * 100)}%` : null;

  const borderTone =
    row.change_kind === 'added'
      ? 'border-l-red-500'
      : row.change_kind === 'resolved'
        ? 'border-l-emerald-500'
        : row.change_kind === 'severity_changed'
          ? 'border-l-amber-500'
          : 'border-l-slate-300';

  return (
    <tr
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
      className={cn(
        'group relative cursor-pointer border-b border-border-subtle border-l-4 transition-colors',
        'hover:bg-hcl-light/40 focus-visible:bg-hcl-light/60 focus-visible:outline-none',
        borderTone,
        row.change_kind === 'resolved' && 'opacity-90',
      )}
    >
      <td className="relative px-3 py-2.5 align-top">
        <SeverityGradient severity={visibleSev} />
        <FindingChangeKindChip kind={row.change_kind} />
      </td>
      <td className="px-3 py-2.5 align-top">
        <CveHoverCard cveId={row.vuln_id}>
          <span className="font-mono text-xs text-hcl-navy group-hover:text-primary">
            {row.vuln_id}
          </span>
        </CveHoverCard>
        <div className="mt-1 flex flex-wrap items-center gap-1">
          {row.kev_current && (
            <span
              title="Currently in CISA KEV catalog"
              className="inline-flex items-center gap-0.5 rounded-full border border-red-300 bg-red-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-red-900"
            >
              <Flame className="h-2.5 w-2.5" aria-hidden />
              KEV
            </span>
          )}
          {showEpss && (
            <span
              title="EPSS exploit probability percentile (FIRST.org)"
              className="inline-flex items-center gap-0.5 rounded-full border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-amber-900"
            >
              <Zap className="h-2.5 w-2.5" aria-hidden />
              EPSS {epssLabel}
            </span>
          )}
          {row.fix_available && (
            <span
              title="A fixed version is published"
              className="inline-flex items-center gap-0.5 rounded-full border border-emerald-300 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-emerald-900"
            >
              <Wrench className="h-2.5 w-2.5" aria-hidden />
              FIX
            </span>
          )}
        </div>
      </td>
      <td className="px-3 py-2.5 align-top">
        {row.change_kind === 'severity_changed' ? (
          <div className="flex items-center gap-1 text-xs">
            <SeverityBadge severity={severityLabel(row.severity_a)} />
            <span className="text-hcl-muted">→</span>
            <SeverityBadge severity={severityLabel(row.severity_b)} />
          </div>
        ) : (
          <SeverityBadge severity={severityLabel(visibleSev)} />
        )}
      </td>
      <td className="px-3 py-2.5 align-top">
        <div className="text-sm text-hcl-navy">{row.component_name}</div>
        <div className="font-mono text-[11px] tabular-nums text-hcl-muted">
          {versionDisplay(row)}
        </div>
      </td>
      <td className="px-3 py-2.5 align-top text-xs text-hcl-muted">
        <AttributionLine text={row.attribution} />
      </td>
    </tr>
  );
}
