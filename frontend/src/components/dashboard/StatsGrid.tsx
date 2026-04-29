import Link from 'next/link';
import { FolderOpen, FileText, AlertTriangle, ArrowUpRight } from 'lucide-react';
import { SkeletonCard } from '@/components/ui/Spinner';
import type { DashboardStats } from '@/types';

interface StatsGridProps {
  stats: DashboardStats | undefined;
  isLoading: boolean;
  error: Error | null;
}

const cards = [
  {
    key: 'total_projects' as const,
    label: 'Total Projects',
    icon: FolderOpen,
    accent: 'text-hcl-blue bg-hcl-light',
    border: 'border-l-hcl-blue',
    href: '/projects',
    linkLabel: 'Open projects',
  },
  {
    key: 'total_sboms' as const,
    label: 'Total SBOMs',
    icon: FileText,
    accent: 'text-hcl-dark bg-hcl-light',
    border: 'border-l-hcl-dark',
    href: '/sboms',
    linkLabel: 'Open SBOMs',
  },
  {
    key: 'total_vulnerabilities' as const,
    label: 'Total Vulnerabilities',
    icon: AlertTriangle,
    accent: 'text-red-600 bg-red-50 dark:bg-red-950/50 dark:text-red-400',
    border: 'border-l-red-500',
    href: '/analysis?tab=runs&status=FAIL',
    linkLabel: 'View runs with findings',
  },
];

export function StatsGrid({ stats, isLoading, error }: StatsGridProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[0, 1, 2].map((i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
        Failed to load stats: {error.message}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {cards.map(({ key, label, icon: Icon, accent, border, href, linkLabel }) => (
        <Link
          key={key}
          href={href}
          aria-label={`${label}: ${stats?.[key]?.toLocaleString() ?? '—'}. ${linkLabel}`}
          className={`group rounded-xl border border-border bg-surface shadow-card border-l-4 ${border} px-6 py-5 transition-shadow hover:shadow-card-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40`}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="text-sm font-medium text-hcl-muted">{label}</p>
              <p className="mt-1 text-3xl font-bold text-hcl-navy">
                {stats?.[key]?.toLocaleString() ?? '—'}
              </p>
              <span className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-primary opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                {linkLabel}
                <ArrowUpRight className="h-3 w-3" aria-hidden />
              </span>
            </div>
            <div className={`shrink-0 p-2.5 rounded-lg ${accent}`}>
              <Icon className="h-5 w-5" aria-hidden />
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
}
