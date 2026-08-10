import Link from 'next/link';
import { Upload, Activity, FolderPlus, GitCompareArrows } from 'lucide-react';
import { cn } from '@/lib/utils';

const linkClass = cn(
  'inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
);

export function DashboardQuickActions() {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
      <Link
        href="/sboms"
        className={cn(linkClass, 'bg-primary text-white shadow-sm hover:bg-hcl-dark')}
      >
        <Upload className="h-4 w-4" aria-hidden />
        Upload SBOM
      </Link>
      <Link
        href="/analysis?tab=runs"
        className={cn(
          linkClass,
          'border border-border bg-surface text-hcl-navy hover:bg-surface-muted',
        )}
      >
        <Activity className="h-4 w-4" aria-hidden />
        Analysis runs
      </Link>
      <Link
        href="/analysis/compare"
        className={cn(
          linkClass,
          'border border-border bg-surface text-hcl-navy hover:bg-surface-muted',
        )}
      >
        <GitCompareArrows className="h-4 w-4" aria-hidden />
        Compare runs
      </Link>
      <Link
        href="/projects"
        className={cn(
          linkClass,
          'border border-dashed border-primary/40 bg-transparent text-primary hover:bg-primary/5',
        )}
      >
        <FolderPlus className="h-4 w-4" aria-hidden />
        Manage projects
      </Link>
    </div>
  );
}
