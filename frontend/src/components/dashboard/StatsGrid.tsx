import Link from 'next/link';
import { useMemo } from 'react';
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  FileText,
  FolderOpen,
  Minus,
  type LucideIcon,
} from 'lucide-react';
import { Skeleton } from '@/components/ui/Spinner';
import { Sparkline } from '@/components/ui/Sparkline';
import { cn } from '@/lib/utils';
import type { DashboardStats, DashboardTrend } from '@/types';

interface StatsGridProps {
  stats: DashboardStats | undefined;
  trend?: DashboardTrend | undefined;
  isLoading: boolean;
  error: Error | null;
}

interface StatCardConfig {
  key: keyof DashboardStats;
  label: string;
  icon: LucideIcon;
  iconClass: string;
  borderClass: string;
  href: string;
  linkLabel: string;
  /** How to derive a sparkline series from the trend data, if any. */
  trendSelector?: (trend: DashboardTrend) => number[];
  /** Tone class for the sparkline color. */
  sparkColor: string;
}

const cards: StatCardConfig[] = [
  {
    key: 'total_projects',
    label: 'Active Projects',
    icon: FolderOpen,
    iconClass: 'bg-hcl-light text-hcl-blue',
    borderClass: 'border-l-hcl-blue',
    href: '/projects',
    linkLabel: 'Open projects',
    sparkColor: 'var(--color-hcl-blue)',
  },
  {
    key: 'total_sboms',
    label: 'Total SBOMs',
    icon: FileText,
    iconClass: 'bg-hcl-light text-hcl-dark dark:text-hcl-blue',
    borderClass: 'border-l-hcl-dark dark:border-l-hcl-blue',
    href: '/sboms',
    linkLabel: 'Open SBOMs',
    sparkColor: 'var(--color-hcl-cyan)',
  },
  {
    key: 'total_vulnerabilities',
    label: 'Total Vulnerabilities',
    icon: AlertTriangle,
    iconClass: 'bg-red-50 text-red-600 dark:bg-red-950/50 dark:text-red-400',
    borderClass: 'border-l-red-500',
    href: '/analysis?tab=runs&status=FAIL',
    linkLabel: 'View runs with findings',
    trendSelector: (t) =>
      t.series.map((p) => p.critical + p.high + p.medium + p.low),
    sparkColor: '#dc2626',
  },
];

function computeDelta(series: number[]): { pct: number; direction: 'up' | 'down' | 'flat' } | null {
  if (series.length < 4) return null;
  const half = Math.floor(series.length / 2);
  const earlier = series.slice(0, half).reduce((s, v) => s + v, 0);
  const later = series.slice(-half).reduce((s, v) => s + v, 0);
  if (earlier === 0 && later === 0) return { pct: 0, direction: 'flat' };
  if (earlier === 0) return { pct: 100, direction: 'up' };
  const pct = ((later - earlier) / earlier) * 100;
  if (Math.abs(pct) < 1) return { pct: 0, direction: 'flat' };
  return { pct, direction: pct > 0 ? 'up' : 'down' };
}

export function StatsGrid({ stats, trend, isLoading, error }: StatsGridProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="space-y-3 rounded-xl border border-border bg-surface p-6 shadow-card"
            aria-hidden="true"
          >
            <Skeleton className="h-3 w-1/3" />
            <Skeleton className="h-8 w-1/2" />
            <Skeleton className="h-3 w-2/3" />
            <Skeleton className="h-8 w-full" />
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200"
      >
        Failed to load stats: {error.message}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
      {cards.map(({ key, label, icon: Icon, iconClass, borderClass, href, linkLabel, trendSelector, sparkColor }) => {
        const value = stats?.[key];
        const series = trend && trendSelector ? trendSelector(trend) : [];
        const delta = computeDelta(series);
        return (
          <StatCard
            key={key}
            label={label}
            value={value}
            icon={Icon}
            iconClass={iconClass}
            borderClass={borderClass}
            href={href}
            linkLabel={linkLabel}
            series={series}
            delta={delta}
            sparkColor={sparkColor}
            isVulnCard={key === 'total_vulnerabilities'}
          />
        );
      })}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: number | undefined;
  icon: LucideIcon;
  iconClass: string;
  borderClass: string;
  href: string;
  linkLabel: string;
  series: number[];
  delta: { pct: number; direction: 'up' | 'down' | 'flat' } | null;
  sparkColor: string;
  isVulnCard: boolean;
}

function StatCard({
  label,
  value,
  icon: Icon,
  iconClass,
  borderClass,
  href,
  linkLabel,
  series,
  delta,
  sparkColor,
  isVulnCard,
}: StatCardProps) {
  // For vuln card, "up" is bad (red); for others, "up" is neutral/positive.
  const deltaTone = useMemo(() => {
    if (!delta || delta.direction === 'flat') return 'text-hcl-muted';
    if (isVulnCard) {
      return delta.direction === 'up'
        ? 'text-red-600 dark:text-red-400'
        : 'text-emerald-600 dark:text-emerald-400';
    }
    return 'text-hcl-muted';
  }, [delta, isVulnCard]);

  return (
    <Link
      href={href}
      aria-label={`${label}: ${value?.toLocaleString() ?? '—'}. ${linkLabel}`}
      className={cn(
        'group relative overflow-hidden rounded-xl border border-l-4 border-border bg-surface px-6 py-5 shadow-card',
        'transition-all duration-base ease-spring',
        'hover:-translate-y-0.5 hover:shadow-card-hover hover:border-l-primary',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
        borderClass,
      )}
    >
      {/* Decorative corner glow on hover */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-12 -top-12 h-32 w-32 rounded-full bg-primary/0 blur-2xl transition-colors duration-slow group-hover:bg-primary/10"
      />
      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-hcl-muted">{label}</p>
          <p className="mt-1 font-metric text-3xl font-bold text-hcl-navy">
            {value?.toLocaleString() ?? '—'}
          </p>
          {delta ? (
            <span className={cn('mt-1 inline-flex items-center gap-1 text-xs font-semibold', deltaTone)}>
              {delta.direction === 'up' && <ArrowUpRight className="h-3 w-3" aria-hidden />}
              {delta.direction === 'down' && <ArrowDownRight className="h-3 w-3" aria-hidden />}
              {delta.direction === 'flat' && <Minus className="h-3 w-3" aria-hidden />}
              {delta.direction === 'flat'
                ? 'No change'
                : `${Math.abs(delta.pct).toFixed(0)}% vs prior`}
            </span>
          ) : (
            <span className="mt-1 inline-block text-xs text-transparent select-none">·</span>
          )}
        </div>
        <div className={cn('shrink-0 rounded-lg p-2.5 transition-transform duration-base ease-spring group-hover:scale-110', iconClass)}>
          <Icon className="h-5 w-5" aria-hidden />
        </div>
      </div>

      {series.length > 0 && (
        <div className="relative mt-3 flex items-end justify-between">
          <Sparkline data={series} width={140} height={32} color={sparkColor} />
          <span className="inline-flex items-center gap-1 text-xs font-medium text-primary opacity-0 transition-opacity duration-base group-hover:opacity-100 group-focus-visible:opacity-100">
            {linkLabel}
            <ArrowUpRight className="h-3 w-3" aria-hidden />
          </span>
        </div>
      )}
      {series.length === 0 && (
        <span className="relative mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary opacity-0 transition-opacity duration-base group-hover:opacity-100 group-focus-visible:opacity-100">
          {linkLabel}
          <ArrowUpRight className="h-3 w-3" aria-hidden />
        </span>
      )}
    </Link>
  );
}
