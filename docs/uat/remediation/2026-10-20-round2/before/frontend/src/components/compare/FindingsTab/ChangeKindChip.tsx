'use client';

import { ArrowDown, ArrowUp, Minus, Plus } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ComponentChangeKind, FindingChangeKind } from '@/types/compare';

const FINDING_KIND: Record<
  FindingChangeKind,
  { label: string; cls: string; Icon: typeof Plus }
> = {
  added: {
    label: 'NEW',
    cls: 'bg-red-50 text-red-900 border-red-300 dark:bg-red-950/60 dark:text-red-100 dark:border-red-700',
    Icon: Plus,
  },
  resolved: {
    label: 'RESOLVED',
    cls: 'bg-emerald-50 text-emerald-900 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-100 dark:border-emerald-700',
    Icon: Minus,
  },
  severity_changed: {
    label: 'SEVERITY',
    cls: 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-100 dark:border-amber-700',
    Icon: ArrowUp,
  },
  unchanged: {
    label: 'UNCHANGED',
    cls: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600',
    Icon: Minus,
  },
};

const COMPONENT_KIND: Record<
  ComponentChangeKind,
  { label: string; cls: string; Icon: typeof Plus }
> = {
  added: {
    label: 'NEW',
    cls: 'bg-red-50 text-red-900 border-red-300',
    Icon: Plus,
  },
  removed: {
    label: 'REMOVED',
    cls: 'bg-slate-100 text-slate-700 border-slate-300',
    Icon: Minus,
  },
  version_bumped: {
    label: 'UPGRADED',
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    Icon: ArrowUp,
  },
  license_changed: {
    label: 'LICENSE',
    cls: 'bg-amber-50 text-amber-900 border-amber-300',
    Icon: ArrowDown,
  },
  hash_changed: {
    label: 'HASH',
    cls: 'bg-red-50 text-red-900 border-red-400',
    Icon: ArrowDown,
  },
  unchanged: {
    label: 'UNCHANGED',
    cls: 'bg-slate-100 text-slate-700 border-slate-300',
    Icon: Minus,
  },
};

const BASE =
  'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider whitespace-nowrap';

export function FindingChangeKindChip({ kind }: { kind: FindingChangeKind }) {
  const entry = FINDING_KIND[kind];
  const { Icon } = entry;
  return (
    <span className={cn(BASE, entry.cls)}>
      <Icon className="h-3 w-3" aria-hidden />
      {entry.label}
    </span>
  );
}

export function ComponentChangeKindChip({ kind }: { kind: ComponentChangeKind }) {
  const entry = COMPONENT_KIND[kind];
  const { Icon } = entry;
  return (
    <span className={cn(BASE, entry.cls)}>
      <Icon className="h-3 w-3" aria-hidden />
      {entry.label}
    </span>
  );
}
