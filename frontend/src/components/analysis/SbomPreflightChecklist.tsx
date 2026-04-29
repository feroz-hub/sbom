'use client';

import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  FileBox,
  Globe,
  Hash,
  Info,
  Package,
  ShieldQuestion,
  type LucideIcon,
} from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { getSbomInfo } from '@/lib/api';
import { cn } from '@/lib/utils';

interface SbomPreflightChecklistProps {
  sbomId: number | null;
}

type Tone = 'pass' | 'warn' | 'info' | 'idle';

interface CheckRow {
  Icon: LucideIcon;
  label: string;
  detail: string;
  tone: Tone;
}

const toneStyles: Record<Tone, { ring: string; iconBg: string; iconText: string }> = {
  pass: {
    ring: 'ring-emerald-200 dark:ring-emerald-900/60',
    iconBg: 'bg-emerald-50 dark:bg-emerald-950/40',
    iconText: 'text-emerald-600 dark:text-emerald-400',
  },
  warn: {
    ring: 'ring-amber-200 dark:ring-amber-900/60',
    iconBg: 'bg-amber-50 dark:bg-amber-950/40',
    iconText: 'text-amber-600 dark:text-amber-400',
  },
  info: {
    ring: 'ring-sky-200 dark:ring-sky-900/60',
    iconBg: 'bg-sky-50 dark:bg-sky-950/40',
    iconText: 'text-sky-600 dark:text-sky-400',
  },
  idle: {
    ring: 'ring-border-subtle',
    iconBg: 'bg-surface-muted',
    iconText: 'text-hcl-muted',
  },
};

/**
 * Estimate analysis runtime (rough heuristic based on observed throughput).
 * NVD averages ~30 components / sec on warm cache; GHSA + OSV are typically
 * 5–10× faster. Returns a string range like "~10–20s".
 */
function estimateRuntime(componentCount: number): { min: number; max: number } {
  if (componentCount === 0) return { min: 0, max: 0 };
  // Optimistic: 50 c/s end-to-end on warm caches; pessimistic 12 c/s cold.
  const min = Math.max(2, Math.ceil(componentCount / 50));
  const max = Math.max(min + 2, Math.ceil(componentCount / 12));
  return { min, max };
}

function formatRuntimeRange(min: number, max: number): string {
  if (min === 0 && max === 0) return '—';
  const fmt = (s: number) => (s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`);
  if (min === max) return `~${fmt(min)}`;
  return `~${fmt(min)} – ${fmt(max)}`;
}

export function SbomPreflightChecklist({ sbomId }: SbomPreflightChecklistProps) {
  const enabled = sbomId != null && Number.isFinite(sbomId) && sbomId > 0;
  const { data, isLoading, error } = useQuery({
    queryKey: ['sbom-info', sbomId],
    queryFn: ({ signal }) => getSbomInfo(sbomId as number, signal),
    enabled,
    retry: false,
    staleTime: 60_000,
  });

  if (!enabled) {
    return (
      <Surface variant="inset">
        <SurfaceContent>
          <p className="flex items-center gap-2 text-sm text-hcl-muted">
            <Info className="h-4 w-4" aria-hidden />
            Pick an SBOM above to preview its scan readiness.
          </p>
        </SurfaceContent>
      </Surface>
    );
  }

  if (isLoading) {
    return (
      <Surface variant="elevated">
        <SurfaceHeader>
          <Skeleton className="h-3 w-32" />
        </SurfaceHeader>
        <SurfaceContent>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-start gap-3">
                <Skeleton className="h-9 w-9 rounded-lg" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-3 w-1/2" />
                  <Skeleton className="h-2 w-2/3" />
                </div>
              </div>
            ))}
          </div>
        </SurfaceContent>
      </Surface>
    );
  }

  if (error) {
    return (
      <Surface variant="elevated" accent>
        <SurfaceContent>
          <p className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300">
            <AlertTriangle className="h-4 w-4 mt-0.5" aria-hidden />
            <span>
              Could not preview SBOM #{sbomId}: {error.message}. You can still run analysis — but
              we won&apos;t be able to estimate runtime.
            </span>
          </p>
        </SurfaceContent>
      </Surface>
    );
  }

  if (!data) return null;

  const { min, max } = estimateRuntime(data.component_count);
  const cpeCoverage: Tone = data.has_cpes ? 'pass' : 'warn';
  const purlCoverage: Tone = data.has_purls ? 'pass' : 'info';

  const checks: CheckRow[] = [
    {
      Icon: FileBox,
      label: data.format,
      detail: data.spec_version ? `Spec v${data.spec_version}` : 'Spec version unknown',
      tone: 'info',
    },
    {
      Icon: Package,
      label: `${data.component_count.toLocaleString()} components`,
      detail:
        data.components_preview.length > 0
          ? `e.g. ${data.components_preview.slice(0, 3).join(', ')}…`
          : 'No components parsed',
      tone: data.component_count > 0 ? 'pass' : 'warn',
    },
    {
      Icon: Globe,
      label:
        data.ecosystems.length > 0
          ? data.ecosystems.slice(0, 4).join(' · ')
          : 'No ecosystems detected',
      detail:
        data.ecosystems.length > 4
          ? `+ ${data.ecosystems.length - 4} more — used for OSV / GHSA matching`
          : 'Used for OSV / GHSA matching',
      tone: data.ecosystems.length > 0 ? 'pass' : 'warn',
    },
    {
      Icon: Hash,
      label: data.has_cpes ? 'CPEs available' : 'No CPEs',
      detail: data.has_cpes
        ? 'NVD will match against component CPEs'
        : 'NVD will fall back to fuzzy CPE generation',
      tone: cpeCoverage,
    },
    {
      Icon: ShieldQuestion,
      label: data.has_purls ? 'PURLs available' : 'No PURLs',
      detail: data.has_purls
        ? 'OSV / GHSA will match against package PURLs'
        : 'OSV / GHSA matching will be limited',
      tone: purlCoverage,
    },
    {
      Icon: CircleDashed,
      label: `Estimated runtime ${formatRuntimeRange(min, max)}`,
      detail:
        data.component_count > 500
          ? 'Large SBOM — first run will be slowest until KEV/EPSS caches warm'
          : 'Streamed live; you can leave this page once a run ID is assigned',
      tone: 'info',
    },
  ];

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-sm font-semibold text-hcl-navy">Pre-flight readiness</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            What we can match against the configured vulnerability sources.
          </p>
        </div>
      </SurfaceHeader>
      <SurfaceContent>
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 stagger">
          {checks.map(({ Icon, label, detail, tone }) => {
            const styles = toneStyles[tone];
            return (
              <li
                key={label}
                className={cn(
                  'flex items-start gap-3 rounded-lg ring-1 px-3 py-2.5 transition-all duration-base',
                  styles.ring,
                )}
              >
                <span
                  className={cn(
                    'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
                    styles.iconBg,
                  )}
                >
                  <Icon className={cn('h-4 w-4', styles.iconText)} aria-hidden />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-hcl-navy">{label}</p>
                  <p className="truncate text-[11px] text-hcl-muted">{detail}</p>
                </div>
              </li>
            );
          })}
        </ul>
      </SurfaceContent>
    </Surface>
  );
}
