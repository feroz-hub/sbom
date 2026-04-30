'use client';

import { AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RunRelationship } from '@/types/compare';

interface Props {
  relationship: RunRelationship;
  onSwap?: () => void;
}

export function RelationshipDescriptor({ relationship, onSwap }: Props) {
  const parts: string[] = [];
  if (relationship.same_sbom) {
    parts.push('Same SBOM, re-scanned');
  } else if (relationship.same_project) {
    parts.push('Same project');
  } else {
    parts.push('Different projects');
  }
  if (relationship.days_between != null) {
    const d = Math.abs(relationship.days_between);
    if (d < 1 / 24) parts.push('< 1h apart');
    else if (d < 1) parts.push(`${Math.round(d * 24)}h apart`);
    else parts.push(`${d.toFixed(1)} days apart`);
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-hcl-muted">
      <span>{parts.join(' · ')}</span>
      {relationship.direction_warning && (
        <button
          type="button"
          onClick={onSwap}
          className={cn(
            'inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2.5 py-0.5 text-[11px] font-medium text-amber-900',
            'hover:bg-amber-100 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200',
          )}
          aria-label="Swap A and B"
        >
          <AlertTriangle className="h-3 w-3" aria-hidden />
          {relationship.direction_warning}
        </button>
      )}
    </div>
  );
}
