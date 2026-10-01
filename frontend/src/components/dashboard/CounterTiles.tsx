'use client';

import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { Boxes, FileCheck2, ScanLine, type LucideIcon } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { getDashboardPosture, type DashboardFilterScope } from '@/lib/api';
import { dashboardDrilldownUrl } from '@/lib/dashboardScopeUrl';
import { useAuth } from '@/hooks/useAuth';

interface TileSpec {
  label: string;
  value: number | undefined;
  icon: LucideIcon;
  href: string;
  hint: string;
  permission: string;
  action: string;
}

/**
 * The three manager counter tiles: SBOMs Stored / Projects Scanned /
 * SBOM Files Analysed. Reuses the ``['dashboard-posture']`` cache (no extra
 * request) and drills each tile to the relevant list view. "Stored" =
 * uploaded; "Analysed" = SBOMs with a completed run; "Scanned" = projects
 * with a completed run.
 */
export interface CounterTilesProps {
  posture?: any;
  isLoading?: boolean;
  scope?: DashboardFilterScope;
}

export function CounterTiles({ posture, isLoading: propsIsLoading, scope }: CounterTilesProps = {}) {
  const router = useRouter();
  const { hasPermission } = useAuth();
  const hasProps = posture !== undefined;

  const queryResult = useQuery({
    queryKey: ['dashboard-posture'],
    queryFn: ({ signal }) => getDashboardPosture(signal),
    enabled: !hasProps,
  });

  const data = hasProps ? posture : queryResult.data;
  const isLoading = hasProps ? !!propsIsLoading : queryResult.isLoading;

  const tiles: TileSpec[] = [
    {
      label: 'Total SBOMs Stored',
      value: data?.total_sboms,
      icon: Boxes,
      href: '/sboms',
      hint: 'All uploaded SBOMs',
      permission: 'sbom:read', action: 'View SBOMs',
    },
    {
      label: 'Total Projects Scanned',
      value: data?.total_applications_scanned,
      icon: ScanLine,
      href: '/projects?scanned=1',
      hint: 'Projects with a completed analysis',
      permission: 'project:read', action: 'View Projects',
    },
    {
      label: 'Total SBOM Files Analysed',
      value: data?.total_sboms_analysed,
      icon: FileCheck2,
      href: '/sboms?analysed=1',
      hint: 'SBOMs with a completed run',
      permission: 'sbom:read', action: 'View analysed SBOMs',
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {tiles.map((t) => {
        const Icon = t.icon;
        return (
          <Surface key={t.label} variant="elevated" elevation={1} className="min-w-0 rounded-2xl p-0 hover:shadow-elev-2">
            <button
              type="button"
              disabled={!hasPermission(t.permission)}
              onClick={() => router.push(dashboardDrilldownUrl(t.href, scope))}
              className="flex min-h-32 w-full items-center gap-4 rounded-2xl px-5 py-4 text-left transition-colors enabled:hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40 disabled:cursor-default"
            >
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-hcl-light text-hcl-blue">
                <Icon className="h-5 w-5" aria-hidden />
              </span>
              <span className="min-w-0">
                <span className="block text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
                  {t.label}
                </span>
                {isLoading || t.value == null ? (
                  <Skeleton className="mt-1 h-7 w-16" />
                ) : (
                  <span className="block font-metric text-3xl font-bold tabular-nums text-hcl-navy">
                    {t.value.toLocaleString()}
                  </span>
                )}
                <span className="mt-1 block text-xs text-hcl-muted">{t.value === 0 ? `No ${t.hint.toLowerCase().replace('all uploaded ', 'uploaded ')} yet` : t.hint}</span>
                {hasPermission(t.permission) && <span className="mt-2 block text-xs font-medium text-hcl-blue">{t.action} →</span>}
              </span>
            </button>
          </Surface>
        );
      })}
    </div>
  );
}
