'use client';

import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, AlertTriangle, AlertCircle, Award, FileWarning, HelpCircle } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { getDashboardLifecycle, getDashboardHealth } from '@/lib/api';

export function LifecycleHealthTiles() {
  const lifecycleQuery = useQuery({
    queryKey: ['dashboard-lifecycle'],
    queryFn: ({ signal }) => getDashboardLifecycle(signal),
  });

  const healthQuery = useQuery({
    queryKey: ['dashboard-health'],
    queryFn: ({ signal }) => getDashboardHealth(signal),
  });

  const lifecycle = lifecycleQuery.data;
  const health = healthQuery.data;
  const loading = lifecycleQuery.isLoading || healthQuery.isLoading;

  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
      {/* Component Lifecycle Card */}
      <Surface variant="elevated" className="p-5">
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Component Lifecycle (EOS/EOL)</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Tracking End-of-Life (EOL), End-of-Support (EOS), and deprecated components
          </p>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="rounded-xl bg-red-50/70 p-3 dark:bg-red-950/20">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-red-800 dark:text-red-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              EOL Components
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-red-700 dark:text-red-400">
                {lifecycle?.eol_components ?? 0}
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-red-600/80 dark:text-red-400/80">Active threat (EOL reached)</div>
          </div>

          <div className="rounded-xl bg-amber-50/70 p-3 dark:bg-amber-950/20">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-amber-800 dark:text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5" />
              Upcoming EOS
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-amber-700 dark:text-amber-400">
                {lifecycle?.eos_upcoming ?? 0}
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-amber-600/80 dark:text-amber-400/80">Retiring in &lt; 90 days</div>
          </div>

          <div className="rounded-xl bg-blue-50/70 p-3 dark:bg-blue-950/20">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-blue-800 dark:text-blue-300">
              <AlertCircle className="h-3.5 w-3.5" />
              Unsupported
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-blue-700 dark:text-blue-400">
                {lifecycle?.unsupported ?? 0}
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-blue-600/80 dark:text-blue-400/80">Deprecated/Unmaintained</div>
          </div>
        </div>
      </Surface>

      {/* SBOM Health Card */}
      <Surface variant="elevated" className="p-5">
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">SBOM Quality &amp; Health</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Metadata completeness score, mandatory fields checklist, and package freshness
          </p>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="rounded-xl bg-emerald-50/70 p-3 dark:bg-emerald-950/20">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">
              <Award className="h-3.5 w-3.5" />
              Completeness
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-emerald-700 dark:text-emerald-400">
                {Math.round(health?.completeness_score ?? 0)}%
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-emerald-600/80 dark:text-emerald-400/80">Average quality rating</div>
          </div>

          <div className="rounded-xl bg-amber-50/70 p-3 dark:bg-amber-950/20">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-amber-800 dark:text-amber-300">
              <FileWarning className="h-3.5 w-3.5" />
              Missing Info
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-amber-700 dark:text-amber-400">
                {health?.missing_metadata ?? 0}
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-amber-600/80 dark:text-amber-400/80">Missing licenses/hashes</div>
          </div>

          <div className="rounded-xl bg-gray-50 p-3 dark:bg-gray-800/40">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">
              <HelpCircle className="h-3.5 w-3.5" />
              Outdated Pkgs
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-7 w-12" />
            ) : (
              <div className="mt-1 font-metric text-2xl font-bold text-gray-700 dark:text-gray-300">
                {health?.outdated_components ?? 0}
              </div>
            )}
            <div className="mt-0.5 text-[9px] text-gray-500">Non-latest releases found</div>
          </div>
        </div>
      </Surface>
    </div>
  );
}
