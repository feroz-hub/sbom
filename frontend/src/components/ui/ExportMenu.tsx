'use client';

import { ChevronDown, Download, type LucideIcon } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { cn } from '@/lib/utils';

export interface ExportMenuItem {
  key: string;
  label: string;
  description?: string;
  Icon?: LucideIcon;
  onSelect: () => void | Promise<void>;
  /** Marks the item as in-flight; disables the row while spinning. */
  loading?: boolean;
  /** Disables the row without showing a spinner. */
  disabled?: boolean;
}

interface ExportMenuProps {
  items: ExportMenuItem[];
  label?: string;
  buttonClassName?: string;
}

/**
 * Single-button export dropdown — collapses the previous PDF / CSV / SARIF
 * trio into one control. Closes on outside click, Escape, or item activation.
 */
export function ExportMenu({ items, label = 'Export', buttonClassName }: ExportMenuProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close on outside click + Escape.
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const anyLoading = items.some((i) => i.loading);

  return (
    <div ref={containerRef} className="relative inline-flex">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-busy={anyLoading || undefined}
        className={cn(
          'inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-surface px-3 text-sm font-medium text-hcl-navy',
          'transition-all duration-base ease-spring',
          'hover:-translate-y-px hover:bg-surface-muted hover:border-hcl-blue/40',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
          'active:translate-y-0 active:scale-[0.98]',
          'motion-reduce:transition-none motion-reduce:hover:translate-y-0 motion-reduce:active:scale-100',
          buttonClassName,
        )}
      >
        <Download className="h-4 w-4" aria-hidden />
        <span>{label}</span>
        {anyLoading ? (
          <svg
            className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none text-hcl-muted"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
          </svg>
        ) : (
          <ChevronDown
            className={cn(
              'h-3.5 w-3.5 text-hcl-muted transition-transform duration-base',
              open && 'rotate-180',
            )}
            aria-hidden
          />
        )}
      </button>

      {open && (
        <ul
          role="menu"
          aria-label={label}
          className={cn(
            'absolute right-0 top-full z-30 mt-1.5 w-64 overflow-hidden rounded-xl',
            'glass-strong shadow-elev-3 motion-scale-in',
            'border border-border-subtle p-1',
          )}
        >
          {items.map((item) => {
            const isDisabled = item.disabled || item.loading;
            return (
              <li key={item.key} role="none">
                <button
                  type="button"
                  role="menuitem"
                  disabled={isDisabled}
                  onClick={async () => {
                    if (isDisabled) return;
                    setOpen(false);
                    await item.onSelect();
                  }}
                  className={cn(
                    'group flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition-colors duration-fast',
                    'focus-visible:outline-none focus-visible:bg-primary/10',
                    isDisabled
                      ? 'cursor-not-allowed opacity-50'
                      : 'hover:bg-primary/5',
                  )}
                >
                  <span
                    className={cn(
                      'flex h-8 w-8 shrink-0 items-center justify-center rounded-md ring-1 ring-border-subtle bg-surface-muted transition-colors',
                      'group-hover:ring-primary/30 group-hover:bg-surface',
                    )}
                  >
                    {item.loading ? (
                      <svg
                        className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none text-primary"
                        fill="none"
                        viewBox="0 0 24 24"
                        aria-hidden
                      >
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                      </svg>
                    ) : item.Icon ? (
                      <item.Icon className="h-3.5 w-3.5 text-hcl-muted group-hover:text-primary" aria-hidden />
                    ) : (
                      <Download className="h-3.5 w-3.5 text-hcl-muted group-hover:text-primary" aria-hidden />
                    )}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-hcl-navy">
                      {item.label}
                    </span>
                    {item.description && (
                      <span className="block truncate text-[11px] text-hcl-muted">
                        {item.description}
                      </span>
                    )}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
