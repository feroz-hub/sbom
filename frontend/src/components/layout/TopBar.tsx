'use client';

import Link from 'next/link';
import { ChevronRight, Menu } from 'lucide-react';
import type { ReactNode } from 'react';
import { useSidebar } from './SidebarContext';
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
          <h1 className="truncate text-lg font-semibold tracking-tight text-hcl-navy md:text-xl">
            {title}
          </h1>
          {subtitle && (
            <div className="mt-0.5 truncate text-xs text-hcl-muted">{subtitle}</div>
          )}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {action}
        <ThemeToggle />
      </div>
    </header>
  );
}
