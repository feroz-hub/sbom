'use client';

import Link from 'next/link';
import {
  AlertTriangle,
  Activity,
  FolderPlus,
  GitCompareArrows,
  ListChecks,
  ShieldAlert,
  Upload,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { PrimaryAction } from '@/types';

interface QuickActionsV2Props {
  /** Server-decided primary action, from `/dashboard/posture`. */
  primaryAction?: PrimaryAction;
}

interface ActionConfig {
  key: PrimaryAction | 'analysis_runs' | 'compare' | 'projects';
  label: string;
  href: string;
  Icon: LucideIcon;
}

const ACTIONS: Record<ActionConfig['key'], ActionConfig> = {
  upload: {
    key: 'upload',
    label: 'Upload SBOM',
    href: '/sboms?action=upload',
    Icon: Upload,
  },
  review_kev: {
    key: 'review_kev',
    label: 'Review KEV-listed findings',
    href: '/analysis?tab=runs&status=FINDINGS&kev=true',
    Icon: ShieldAlert,
  },
  review_critical: {
    key: 'review_critical',
    label: 'Review critical findings',
    href: '/analysis?tab=runs&status=FINDINGS&severity=CRITICAL',
    Icon: AlertTriangle,
  },
  view_top_sboms: {
    key: 'view_top_sboms',
    label: 'View top vulnerable SBOMs',
    href: '/analysis?tab=runs&status=FINDINGS',
    Icon: ListChecks,
  },
  analysis_runs: {
    key: 'analysis_runs',
    label: 'Analysis runs',
    href: '/analysis?tab=runs',
    Icon: Activity,
  },
  compare: {
    key: 'compare',
    label: 'Compare runs',
    href: '/analysis/compare',
    Icon: GitCompareArrows,
  },
  projects: {
    key: 'projects',
    label: 'Manage projects',
    href: '/projects',
    Icon: FolderPlus,
  },
};

const linkBase = cn(
  'inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
);

/**
 * Quick actions row with a state-driven primary CTA.
 *
 * The primary swaps based on `primary_action` from the posture payload —
 * KEV present → "Review KEV-listed findings", criticals only → "Review
 * critical findings", and so on. Default outline styling for the others
 * keeps the row visually quiet so the primary stands out without
 * shouting; one accent button per row, never two.
 *
 * Mapping locked in `docs/dashboard-redesign.md` §4.
 */
export function QuickActionsV2({ primaryAction = 'upload' }: QuickActionsV2Props) {
  const primary = ACTIONS[primaryAction] ?? ACTIONS.upload;
  // Outline actions = the four canonical secondary aids, minus whichever
  // one is currently primary so we don't duplicate it.
  const secondaryKeys: ActionConfig['key'][] = (() => {
    const all: ActionConfig['key'][] = [
      'upload',
      'analysis_runs',
      'compare',
      'projects',
    ];
    return all.filter((k) => k !== primary.key);
  })();

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
      <Link
        href={primary.href}
        className={cn(linkBase, 'bg-primary text-white shadow-sm hover:bg-hcl-dark')}
      >
        <primary.Icon className="h-4 w-4" aria-hidden />
        {primary.label}
      </Link>
      {secondaryKeys.map((key) => {
        const a = ACTIONS[key];
        const dashed = key === 'projects';
        return (
          <Link
            key={key}
            href={a.href}
            className={cn(
              linkBase,
              dashed
                ? 'border border-dashed border-primary/40 bg-transparent text-primary hover:bg-primary/5'
                : 'border border-border bg-surface text-hcl-navy hover:bg-surface-muted',
            )}
          >
            <a.Icon className="h-4 w-4" aria-hidden />
            {a.label}
          </Link>
        );
      })}
    </div>
  );
}
