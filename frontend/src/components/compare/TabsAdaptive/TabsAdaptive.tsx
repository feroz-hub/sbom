'use client';

import { cn } from '@/lib/utils';
import type { CompareResult, CompareTab, FindingDiffRow } from '@/types/compare';

interface Props {
  current: CompareTab;
  setTab: (t: CompareTab) => void;
  result: CompareResult;
}

const LABEL: Record<CompareTab, string> = {
  findings: 'Findings',
  components: 'Components',
  delta: 'Posture detail',
};

/**
 * Compare-page tab strip with activity indicators.
 *
 *   - Active tab: bold + accent-coloured background.
 *   - Inactive tab with content: regular weight + count.
 *   - Inactive tab with zero items: muted, count `(0)` greyed.
 *   - Findings tab gains a coloured dot when there are critical (red) or
 *     high (amber) added findings — drawing attention to actionable risk.
 */
export function TabsAdaptive({ current, setTab, result }: Props) {
  const findingCount = result.findings.filter(
    (f) => f.change_kind !== 'unchanged',
  ).length;
  const componentCount = result.components.filter(
    (c) => c.change_kind !== 'unchanged',
  ).length;
  const dot = pickDotColor(result.findings);

  const counts: Record<CompareTab, number | null> = {
    findings: findingCount,
    components: componentCount,
    delta: null,
  };

  return (
    <div role="tablist" aria-label="Compare views" className="flex gap-1">
      {(['findings', 'components', 'delta'] as const).map((t) => {
        const active = current === t;
        const count = counts[t];
        const isZero = count === 0;
        return (
          <button
            key={t}
            role="tab"
            aria-selected={active}
            onClick={() => setTab(t)}
            className={cn(
              'group inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
              active
                ? 'bg-hcl-light text-hcl-navy font-semibold'
                : isZero
                  ? 'text-hcl-muted/60 hover:bg-surface-muted hover:text-hcl-muted'
                  : 'text-hcl-muted hover:bg-surface-muted hover:text-hcl-navy',
            )}
          >
            <span>{LABEL[t]}</span>
            {count !== null && (
              <span
                className={cn(
                  'tabular-nums text-[11px]',
                  isZero ? 'text-hcl-muted/60' : 'text-hcl-muted',
                  active && 'text-hcl-navy',
                )}
              >
                ({count})
              </span>
            )}
            {t === 'findings' && dot && (
              <span
                aria-label={dot.label}
                title={dot.label}
                className={cn('inline-block h-1.5 w-1.5 rounded-full', dot.cls)}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}

/**
 * Returns a dot indicator for the Findings tab when added findings include
 * a critical (red) or high (amber). Otherwise null.
 */
function pickDotColor(rows: FindingDiffRow[]): { cls: string; label: string } | null {
  let critical = 0;
  let high = 0;
  for (const r of rows) {
    if (r.change_kind !== 'added') continue;
    const sev = r.severity_b ?? r.severity_a;
    if (sev === 'critical') critical += 1;
    else if (sev === 'high') high += 1;
  }
  if (critical > 0) {
    return {
      cls: 'bg-red-600 dark:bg-red-400',
      label: `${critical} new critical finding${critical === 1 ? '' : 's'}`,
    };
  }
  if (high > 0) {
    return {
      cls: 'bg-amber-500 dark:bg-amber-400',
      label: `${high} new high-severity finding${high === 1 ? '' : 's'}`,
    };
  }
  return null;
}
