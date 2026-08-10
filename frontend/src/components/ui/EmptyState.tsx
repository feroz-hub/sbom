import { cn } from '@/lib/utils';
import {
  FileSearch,
  FolderOpen,
  Inbox,
  PackageOpen,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { type ReactNode } from 'react';

export type EmptyStateIllustration =
  | 'no-sboms'
  | 'no-runs'
  | 'no-findings'
  | 'no-projects'
  | 'no-results'
  | 'all-clear'
  | 'generic';

const illustrationMap: Record<EmptyStateIllustration, { Icon: LucideIcon; tone: string; label: string }> = {
  'no-sboms': { Icon: PackageOpen, tone: 'text-hcl-blue', label: 'No SBOMs yet' },
  'no-runs': { Icon: ScanSearch, tone: 'text-hcl-blue', label: 'No analysis runs' },
  'no-findings': { Icon: ShieldCheck, tone: 'text-emerald-500', label: 'No findings' },
  'no-projects': { Icon: FolderOpen, tone: 'text-hcl-blue', label: 'No projects' },
  'no-results': { Icon: FileSearch, tone: 'text-hcl-muted', label: 'No matches' },
  'all-clear': { Icon: ShieldCheck, tone: 'text-emerald-500', label: 'All clear' },
  generic: { Icon: Inbox, tone: 'text-hcl-muted', label: 'Nothing here' },
};

interface EmptyStateProps {
  illustration?: EmptyStateIllustration;
  title: string;
  description?: ReactNode;
  /** Primary CTA — typically a Button or Link. */
  action?: ReactNode;
  /** Secondary action, displayed alongside the primary. */
  secondaryAction?: ReactNode;
  /** Compact mode — reduced padding for inline placement (e.g., empty table cell). */
  compact?: boolean;
  className?: string;
}

/**
 * Friendly empty / zero-data state with iconography, copy, and CTAs.
 *
 * Use when a query returns no results, when a feature has no content yet,
 * or when an action has cleared everything successfully.
 */
export function EmptyState({
  illustration = 'generic',
  title,
  description,
  action,
  secondaryAction,
  compact = false,
  className,
}: EmptyStateProps) {
  const { Icon, tone, label } = illustrationMap[illustration];
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        'flex flex-col items-center justify-center text-center motion-rise',
        compact ? 'gap-2 py-8 px-4' : 'gap-4 py-14 px-6',
        className,
      )}
    >
      <div
        aria-hidden="true"
        className={cn(
          'relative flex items-center justify-center rounded-full',
          compact ? 'h-12 w-12' : 'h-20 w-20',
          'bg-gradient-to-br from-hcl-light to-surface-muted',
          'shadow-elev-1',
        )}
      >
        <Icon className={cn(tone, compact ? 'h-6 w-6' : 'h-10 w-10')} />
        {!compact && (
          <Sparkles
            className="absolute -right-1 -top-1 h-4 w-4 text-hcl-cyan/70 motion-fade-in"
            aria-hidden="true"
          />
        )}
        <span className="sr-only">{label}</span>
      </div>
      <div className={cn('space-y-1.5', compact ? 'max-w-sm' : 'max-w-md')}>
        <h3
          className={cn(
            'font-semibold text-hcl-navy',
            compact ? 'text-sm' : 'text-base',
          )}
        >
          {title}
        </h3>
        {description && (
          <p className={cn('text-hcl-muted', compact ? 'text-xs' : 'text-sm leading-relaxed')}>
            {description}
          </p>
        )}
      </div>
      {(action || secondaryAction) && (
        <div className={cn('flex items-center gap-2', compact ? 'mt-1' : 'mt-2')}>
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}
