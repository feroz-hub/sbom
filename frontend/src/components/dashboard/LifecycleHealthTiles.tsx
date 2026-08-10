'use client';

import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, AlertTriangle, AlertCircle, Award, FileWarning, HelpCircle, ShieldCheck } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { getDashboardLifecycle, getDashboardHealth, getDashboardVex } from '@/lib/api';

export interface LifecycleHealthTilesProps {
  lifecycle?: any;
  health?: any;
  vex?: any;
  isLoading?: boolean;
}

export function LifecycleHealthTiles({
  lifecycle: propsLifecycle,
  health: propsHealth,
  vex: propsVex,
  isLoading: propsIsLoading,
}: LifecycleHealthTilesProps = {}) {
  const hasProps = propsLifecycle !== undefined && propsHealth !== undefined && propsVex !== undefined;

  const lifecycleQuery = useQuery({
    queryKey: ['dashboard-lifecycle'],
    queryFn: ({ signal }) => getDashboardLifecycle(signal),
    enabled: !hasProps,
  });

  const healthQuery = useQuery({
    queryKey: ['dashboard-health'],
    queryFn: ({ signal }) => getDashboardHealth(signal),
    enabled: !hasProps,
  });

  const vexQuery = useQuery({
    queryKey: ['dashboard-vex'],
    queryFn: ({ signal }) => getDashboardVex(signal),
    enabled: !hasProps,
  });

  const lifecycle = hasProps ? propsLifecycle : lifecycleQuery.data;
  const health = hasProps ? propsHealth : healthQuery.data;
  const vex = hasProps ? propsVex : vexQuery.data;
  const loading = hasProps ? !!propsIsLoading : (lifecycleQuery.isLoading || healthQuery.isLoading || vexQuery.isLoading);
  const lifecycleError = hasProps ? false : lifecycleQuery.isError;
  const lifecycleEmpty = !loading && !lifecycleError && (lifecycle?.total_components ?? 0) === 0;

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      {/* Component Lifecycle Card */}
      <Surface variant="elevated" className="p-5">
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Component Lifecycle (EOS/EOL)</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Tracking End-of-Life (EOL), End-of-Support (EOS), and deprecated components
          </p>
        </div>

        {lifecycleError ? (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900 dark:bg-red-950/20 dark:text-red-200">
            Lifecycle metrics could not be loaded. Retry from the dashboard or refresh this page.
          </div>
        ) : lifecycleEmpty ? (
          <div className="mt-4 rounded-lg border border-gray-200 bg-gray-50 p-3 text-xs text-gray-700 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-300">
            No component lifecycle data is available yet.
          </div>
        ) : null}

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

        <div className="mt-3 grid grid-cols-3 gap-3">
          {([
            ['Supported', lifecycle?.supported_count ?? 0, 'text-emerald-700 dark:text-emerald-300'],
            ['Deprecated', lifecycle?.deprecated_count ?? 0, 'text-orange-700 dark:text-orange-300'],
            ['Unknown', lifecycle?.unknown_count ?? 0, 'text-gray-700 dark:text-gray-300'],
            ['EOF', lifecycle?.eof_count ?? 0, 'text-rose-700 dark:text-rose-300'],
            ['EOL Soon', lifecycle?.eol_soon_count ?? 0, 'text-amber-700 dark:text-amber-300'],
            ['Possibly Unmaintained', lifecycle?.possibly_unmaintained_count ?? 0, 'text-yellow-700 dark:text-yellow-300'],
            ['Stale Data', lifecycle?.stale_lifecycle_count ?? 0, 'text-slate-700 dark:text-slate-300'],
          ] as const).map(([label, value, color]) => (
            <div key={label} className="rounded-lg border border-gray-200/70 p-2 dark:border-gray-800">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">{label}</div>
              {loading ? (
                <Skeleton className="mt-2 h-5 w-10" />
              ) : (
                <div className={`mt-1 font-metric text-xl font-semibold ${color}`}>{value}</div>
              )}
            </div>
          ))}
        </div>

        {!loading && (lifecycle?.recommended_upgrades?.length ?? 0) > 0 ? (
          <div className="mt-3 border-t border-gray-200 pt-3 dark:border-gray-800">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">Recommended Upgrades</div>
            <div className="mt-2 space-y-1.5">
              {lifecycle?.recommended_upgrades.slice(0, 3).map((item: any) => (
                <div key={`${item.id}-${item.name}`} className="flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-hcl-navy">{item.name}</span>
                  <span className="shrink-0 text-hcl-muted">{item.recommended_version ?? item.lifecycle_status}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}
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

      {/* VEX Summary Card */}
      <Surface variant="elevated" className="p-5">
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">VEX Exploitability</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Product-context affected, fixed, and not-affected vulnerability statements
          </p>
        </div>

        {vexQuery.isError ? (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900 dark:bg-red-950/20 dark:text-red-200">
            VEX metrics could not be loaded.
          </div>
        ) : !loading && !vex && !vexQuery.isError ? (
          <div className="mt-4 rounded-lg border border-gray-200 bg-gray-50 p-3 text-xs text-gray-700 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-300">
            No VEX statements have been imported yet.
          </div>
        ) : null}

        <div className="mt-4 grid grid-cols-3 gap-3">
          {([
            ['Affected', vex?.affected_count ?? 0, 'text-red-700 dark:text-red-300'],
            ['Not Affected', vex?.not_affected_count ?? 0, 'text-emerald-700 dark:text-emerald-300'],
            ['Fixed', vex?.fixed_count ?? 0, 'text-blue-700 dark:text-blue-300'],
            ['Investigating', vex?.under_investigation_count ?? 0, 'text-amber-700 dark:text-amber-300'],
            ['Unknown', vex?.unknown_count ?? 0, 'text-gray-700 dark:text-gray-300'],
            ['Requires Action', vex?.vulnerabilities_requiring_action ?? 0, 'text-rose-700 dark:text-rose-300'],
          ] as const).map(([label, value, color]) => (
            <div key={label} className="rounded-lg border border-gray-200/70 p-2 dark:border-gray-800">
              <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                <ShieldCheck className="h-3.5 w-3.5" />
                {label}
              </div>
              {loading ? (
                <Skeleton className="mt-2 h-5 w-10" />
              ) : (
                <div className={`mt-1 font-metric text-xl font-semibold ${color}`}>{value}</div>
              )}
            </div>
          ))}
        </div>

        {!loading && (vex?.top_affected_components?.length ?? 0) > 0 ? (
          <div className="mt-3 border-t border-gray-200 pt-3 dark:border-gray-800">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">Top Affected</div>
            <div className="mt-2 space-y-1.5">
              {vex?.top_affected_components.slice(0, 3).map((item: any) => (
                <div key={`${item.id}-${item.vulnerability_id}`} className="flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-hcl-navy">{item.component_name ?? 'Component'}</span>
                  <span className="shrink-0 text-hcl-muted">{item.vulnerability_id}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </Surface>
    </div>
  );
}
