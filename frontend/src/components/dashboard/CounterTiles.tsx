'use client';

import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { Boxes, FileCheck2, ScanLine, type LucideIcon } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { getDashboardPosture } from '@/lib/api';

interface TileSpec {
  label: string;
  value: number | undefined;
  icon: LucideIcon;
  href: string;
  hint: string;
}

/**
 * The three manager counter tiles: SBOMs Stored / Applications Scanned /
 * SBOMs Analysed. Reuses the ``['dashboard-posture']`` cache (no extra
 * request) and drills each tile to the relevant list view. "Stored" =
 * uploaded; "Analysed" = SBOMs with a completed run; "Scanned" = applications
 * (projects) with a completed run.
 */
export interface CounterTilesProps {
  posture?: any;
  isLoading?: boolean;
}

export function CounterTiles({ posture, isLoading: propsIsLoading }: CounterTilesProps = {}) {
  const router = useRouter();
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
    },
    {
      label: 'Total Applications Scanned',
      value: data?.total_applications_scanned,
      icon: ScanLine,
      href: '/projects',
      hint: 'Projects with a completed analysis',
    },
    {
      label: 'Total SBOMs Analysed',
      value: data?.total_sboms_analysed,
      icon: FileCheck2,
      href: '/analysis?tab=runs',
      hint: 'SBOMs with a completed run',
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {tiles.map((t) => {
        const Icon = t.icon;
        return (
          <Surface key={t.label} variant="elevated" className="p-0">
            <button
              type="button"
              onClick={() => router.push(t.href)}
              className="flex w-full items-center gap-4 rounded-xl px-5 py-4 text-left transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
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
                  <span className="block font-metric text-2xl font-bold tabular-nums text-hcl-navy">
                    {t.value.toLocaleString()}
                  </span>
                )}
                <span className="mt-0.5 block text-[10px] text-hcl-muted">{t.hint}</span>
              </span>
            </button>
          </Surface>
        );
      })}
    </div>
  );
}
