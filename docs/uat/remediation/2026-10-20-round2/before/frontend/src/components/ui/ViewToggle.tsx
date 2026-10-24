'use client';

import { LayoutGrid, List } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ViewMode } from '@/hooks/useViewMode';

interface ViewToggleProps {
  value: ViewMode;
  onChange: (mode: ViewMode) => void;
  /** Names the collection, e.g. "projects" — used for the group's aria-label. */
  label?: string;
  className?: string;
}

const OPTIONS: { mode: ViewMode; icon: typeof List; text: string }[] = [
  { mode: 'list', icon: List, text: 'List' },
  { mode: 'grid', icon: LayoutGrid, text: 'Grid' },
];

/**
 * Segmented list/grid switch.
 *
 * A radio group rather than two buttons: the two options are mutually
 * exclusive states of one setting, so arrow-key navigation and a single tab
 * stop are the behaviour a keyboard user expects. The labels stay visible from
 * `sm` up — icon-only segmented controls are a common source of "which one am
 * I on" confusion, and there is room for the words here.
 */
export function ViewToggle({ value, onChange, label = 'items', className }: ViewToggleProps) {
  return (
    <div
      role="radiogroup"
      aria-label={`View ${label} as a list or grid`}
      className={cn('inline-flex rounded-lg border border-hcl-border bg-surface p-0.5', className)}
    >
      {OPTIONS.map(({ mode, icon: Icon, text }) => {
        const active = value === mode;
        return (
          <button
            key={mode}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(mode)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
                event.preventDefault();
                onChange(mode === 'list' ? 'grid' : 'list');
              }
            }}
            title={`${text} view`}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
              active
                ? 'bg-hcl-blue text-white shadow-sm'
                : 'text-hcl-muted hover:bg-hcl-light hover:text-hcl-navy',
            )}
          >
            <Icon className="h-3.5 w-3.5" aria-hidden />
            <span className="hidden sm:inline">{text}</span>
          </button>
        );
      })}
    </div>
  );
}
