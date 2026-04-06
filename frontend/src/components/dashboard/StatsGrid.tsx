import { FolderOpen, FileText, AlertTriangle } from 'lucide-react';
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
  },
  {
    key: 'total_sboms' as const,
    label: 'Total SBOMs',
    icon: FileText,
    accent: 'text-hcl-dark bg-hcl-light',
    border: 'border-l-hcl-dark',
  },
  {
    key: 'total_vulnerabilities' as const,
    label: 'Total Vulnerabilities',
    icon: AlertTriangle,
    accent: 'text-red-600 bg-red-50',
    border: 'border-l-red-500',
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
      <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load stats: {error.message}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {cards.map(({ key, label, icon: Icon, accent, border }) => (
        <div
          key={key}
          className={`bg-white rounded-xl border border-hcl-border shadow-card border-l-4 ${border} px-6 py-5`}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-medium text-hcl-muted">{label}</p>
              <p className="mt-1 text-3xl font-bold text-hcl-navy">
                {stats?.[key]?.toLocaleString() ?? '—'}
              </p>
            </div>
            <div className={`p-2.5 rounded-lg ${accent}`}>
              <Icon className="h-5 w-5" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
