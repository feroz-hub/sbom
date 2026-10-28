'use client';

import { LayoutList, Layers, ShieldAlert } from 'lucide-react';
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
    description: 'Configure, monitor and review scans',
    icon: Layers,
  },
  {
    id: 'runs',
    label: 'All runs',
    description: 'History, filters, compare & export',
    icon: LayoutList,
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    description: 'Portfolio-wide, grouped by project & product',
    icon: ShieldAlert,
  },
];

export function AnalysisHubTabs({ active, onChange }: AnalysisHubTabsProps) {
  return (
    <div
      role="tablist"
      aria-label="Analysis sections"
      className="flex gap-2 sm:gap-3"
    >
      {tabs.map(({ id, label, description, icon: Icon }) => {
        const isActive = active === id;
        return (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={isActive}
            aria-controls={`analysis-panel-${id}`}
            id={`analysis-tab-${id}`}
            tabIndex={isActive ? 0 : -1}
            onClick={() => onChange(id)}
            onKeyDown={(event) => {
              const direction = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
              const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
                : direction ? (tabs.findIndex(tab => tab.id === id) + direction + tabs.length) % tabs.length : -1;
              if (next < 0) return;
              event.preventDefault();
              onChange(tabs[next].id);
              document.getElementById(`analysis-tab-${tabs[next].id}`)?.focus();
            }}
            className={cn(
              'flex min-w-0 flex-1 items-center gap-2 rounded-xl border px-3 py-2 text-left transition-colors sm:gap-3 sm:px-4 sm:py-3',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
              isActive
                ? 'border-hcl-blue bg-hcl-light/80 shadow-md ring-1 ring-hcl-blue/20'
                : 'border-hcl-border bg-surface hover:bg-hcl-light/40',
            )}
          >
            <div
              className={cn(
                'hidden h-8 w-8 shrink-0 items-center justify-center rounded-lg sm:flex',
                isActive ? 'bg-hcl-blue text-white' : 'bg-hcl-light text-hcl-muted',
              )}
            >
              <Icon className="h-5 w-5" aria-hidden />
            </div>
            <span className="min-w-0">
              <span className="block text-xs font-semibold text-hcl-navy sm:text-sm">{label}</span>
              <span className="mt-0.5 hidden text-xs text-hcl-muted sm:block">{description}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
