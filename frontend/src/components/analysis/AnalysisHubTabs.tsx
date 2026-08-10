'use client';

import { LayoutList, Layers } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { AnalysisHubTab } from '@/hooks/useAnalysisUrlState';

interface AnalysisHubTabsProps {
  active: AnalysisHubTab;
  onChange: (tab: AnalysisHubTab) => void;
}

const tabs: { id: AnalysisHubTab; label: string; description: string; icon: typeof LayoutList }[] = [
  {
    id: 'consolidated',
    label: 'Consolidated scan',
    description: 'Multi-source scan (NVD, GHSA, OSV, VulDB)',
    icon: Layers,
  },
  {
    id: 'runs',
    label: 'All runs',
    description: 'History, filters, compare & export',
    icon: LayoutList,
  },
];

export function AnalysisHubTabs({ active, onChange }: AnalysisHubTabsProps) {
  return (
    <div
      role="tablist"
      aria-label="Analysis sections"
      className="flex flex-col gap-2 sm:flex-row sm:gap-3"
    >
      {tabs.map(({ id, label, description, icon: Icon }) => {
        const isActive = active === id;
        return (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={isActive}
            id={`analysis-tab-${id}`}
            tabIndex={isActive ? 0 : -1}
            onClick={() => onChange(id)}
            className={cn(
              'flex flex-1 items-start gap-3 rounded-xl border px-4 py-3 text-left transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
              isActive
                ? 'border-hcl-blue bg-hcl-light/80 shadow-md ring-1 ring-hcl-blue/20'
                : 'border-hcl-border bg-surface hover:bg-hcl-light/40',
            )}
          >
            <div
              className={cn(
                'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
                isActive ? 'bg-hcl-blue text-white' : 'bg-hcl-light text-hcl-muted',
              )}
            >
              <Icon className="h-5 w-5" aria-hidden />
            </div>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-hcl-navy">{label}</span>
              <span className="mt-0.5 block text-xs text-hcl-muted">{description}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
