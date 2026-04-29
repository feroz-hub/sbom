'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import {
  LayoutDashboard,
  FolderOpen,
  FileText,
  Activity,
  GitCompareArrows,
  Search,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const NAV: { href: string; label: string; hint: string; icon: typeof LayoutDashboard }[] = [
  { href: '/', label: 'Dashboard', hint: 'Overview and metrics', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', hint: 'Manage projects', icon: FolderOpen },
  { href: '/sboms', label: 'SBOMs', hint: 'Upload and manage SBOM files', icon: FileText },
  { href: '/analysis?tab=runs', label: 'Analysis runs', hint: 'History, filters, export', icon: Activity },
  { href: '/analysis/compare', label: 'Compare runs', hint: 'Diff two analysis runs', icon: GitCompareArrows },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery('');
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return NAV;
    return NAV.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.hint.toLowerCase().includes(q) ||
        item.href.includes(q),
    );
  }, [query]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center p-4 pt-[15vh]" role="dialog" aria-modal="true" aria-labelledby="command-palette-title">
      <button type="button" className="absolute inset-0 bg-black/50 backdrop-blur-sm" aria-label="Close command palette" onClick={() => setOpen(false)} />
      <div className="relative z-[101] w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-xl">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <Search className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
          <input
            ref={inputRef}
            id="command-palette-title"
            type="search"
            placeholder="Search pages…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="min-w-0 flex-1 bg-transparent py-2 text-sm text-hcl-navy placeholder:text-hcl-muted focus:outline-none"
            autoComplete="off"
            aria-label="Search navigation"
          />
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="rounded-lg p-2 text-hcl-muted hover:bg-surface-muted"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="border-b border-border px-4 py-2 text-xs text-hcl-muted">
          <kbd className="rounded border border-border bg-surface-muted px-1 font-mono">⌘</kbd>
          <kbd className="ml-1 rounded border border-border bg-surface-muted px-1 font-mono">K</kbd>
          <span className="ml-2">Toggle · Esc to close</span>
        </p>
        <ul className="max-h-[min(50vh,320px)] overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <li className="px-4 py-6 text-center text-sm text-hcl-muted">No matches</li>
          ) : (
            filtered.map((item) => {
              const Icon = item.icon;
              return (
                <li key={`${item.href}-${item.label}`}>
                  <Link
                    href={item.href}
                    onClick={() => setOpen(false)}
                    className={cn(
                      'flex items-center gap-3 px-4 py-2.5 text-sm transition-colors hover:bg-hcl-light/80',
                      'focus-visible:outline-none focus-visible:bg-hcl-light/80',
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="font-medium text-hcl-navy">{item.label}</span>
                      <span className="block truncate text-xs text-hcl-muted">{item.hint}</span>
                    </span>
                  </Link>
                </li>
              );
            })
          )}
        </ul>
      </div>
    </div>
  );
}
