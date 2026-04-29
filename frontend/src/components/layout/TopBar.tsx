'use client';

import Link from 'next/link';
import { ChevronRight, Menu, Search } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { useSidebar } from './SidebarContext';
import { openCommandPalette } from './CommandPalette';
import { ThemeToggle } from '@/components/theme/ThemeToggle';
import { cn } from '@/lib/utils';

export interface BreadcrumbItem {
  label: string;
  /** Omit for the current page (not a link). */
  href?: string;
}

interface TopBarProps {
  title: string;
  action?: ReactNode;
  subtitle?: ReactNode;
  /** Wayfinding trail; last item is usually the current page (no `href`). */
  breadcrumbs?: BreadcrumbItem[];
}

export function TopBar({ title, action, subtitle, breadcrumbs }: TopBarProps) {
  const { openMobile } = useSidebar();
  const [isMac, setIsMac] = useState(false);

  // Detect platform on mount so we can show ⌘K vs Ctrl K accurately.
  useEffect(() => {
    if (typeof navigator === 'undefined') return;
    setIsMac(/mac|iphone|ipad|ipod/i.test(navigator.platform || navigator.userAgent || ''));
  }, []);

  return (
    <header
      className={cn(
        'sticky top-0 z-20 border-b border-border shadow-topbar',
        'bg-surface/85 backdrop-blur-md supports-[backdrop-filter]:bg-surface/75',
        'px-4 py-3 md:px-6 md:py-4',
        'flex items-center justify-between gap-3',
      )}
    >
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <button
          type="button"
          onClick={openMobile}
          aria-label="Open navigation"
          className={cn(
            'md:hidden flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
            'text-hcl-navy hover:bg-surface-muted transition-colors motion-reduce:transition-none',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
          )}
        >
          <Menu className="h-5 w-5" aria-hidden="true" />
        </button>

        <div className="h-6 w-1 shrink-0 rounded-full bg-gradient-to-b from-hcl-blue to-hcl-cyan" aria-hidden="true" />

        <div className="min-w-0 flex-1">
          {breadcrumbs && breadcrumbs.length > 0 && (
            <nav aria-label="Breadcrumb" className="mb-1">
              <ol className="flex flex-wrap items-center gap-x-1 gap-y-0.5 text-xs text-hcl-muted">
                {breadcrumbs.map((item, i) => {
                  const isLast = i === breadcrumbs.length - 1;
                  return (
                    <li key={`${item.label}-${i}`} className="flex items-center gap-1">
                      {i > 0 && (
                        <ChevronRight className="h-3.5 w-3.5 shrink-0 opacity-50" aria-hidden />
                      )}
                      {item.href ? (
                        <Link
                          href={item.href}
                          className="max-w-[min(100vw-8rem,28rem)] truncate rounded px-0.5 font-medium text-hcl-muted transition-colors hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                        >
                          {item.label}
                        </Link>
                      ) : (
                        <span
                          className={cn(
                            'max-w-[min(100vw-8rem,28rem)] truncate font-medium',
                            isLast ? 'text-foreground' : 'text-hcl-muted',
                          )}
                          aria-current={isLast ? 'page' : undefined}
                        >
                          {item.label}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ol>
            </nav>
          )}
          <h1 className="truncate text-lg font-semibold tracking-display text-hcl-navy md:text-display-sm">
            {title}
          </h1>
          {subtitle && (
            <div className="mt-0.5 truncate text-xs text-hcl-muted">{subtitle}</div>
          )}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={openCommandPalette}
          aria-label="Open command palette"
          title="Search · Cmd+K"
          className={cn(
            'group hidden items-center gap-2 rounded-lg border border-border bg-surface/70 px-3 h-10 sm:inline-flex',
            'text-xs text-hcl-muted transition-all duration-base ease-spring',
            'hover:-translate-y-px hover:border-hcl-blue/50 hover:bg-surface hover:text-hcl-navy hover:shadow-elev-2',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
          )}
        >
          <Search className="h-3.5 w-3.5 transition-colors group-hover:text-primary" aria-hidden />
          <span className="hidden md:inline">Search anything…</span>
          <span className="ml-1 hidden items-center gap-0.5 lg:flex">
            <kbd className="font-mono inline-flex h-5 min-w-[1.1rem] items-center justify-center rounded border border-border bg-surface-muted px-1 text-[10px] font-semibold text-hcl-navy">
              {isMac ? '⌘' : 'Ctrl'}
            </kbd>
            <kbd className="font-mono inline-flex h-5 min-w-[1.1rem] items-center justify-center rounded border border-border bg-surface-muted px-1 text-[10px] font-semibold text-hcl-navy">
              K
            </kbd>
          </span>
        </button>
        <button
          type="button"
          onClick={openCommandPalette}
          aria-label="Open command palette"
          className={cn(
            'inline-flex sm:hidden h-10 w-10 items-center justify-center rounded-lg',
            'text-hcl-navy hover:bg-surface-muted transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
          )}
        >
          <Search className="h-4 w-4" aria-hidden />
        </button>
        {action}
        <ThemeToggle />
      </div>
    </header>
  );
}
