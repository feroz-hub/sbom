'use client';

import { Menu } from 'lucide-react';
import type { ReactNode } from 'react';
import { useSidebar } from './SidebarContext';
import { cn } from '@/lib/utils';

interface TopBarProps {
  title: string;
  /** Optional right-aligned action area (buttons, filters, etc.). */
  action?: ReactNode;
  /** Optional subtitle / breadcrumb region rendered under the title. */
  subtitle?: ReactNode;
}

export function TopBar({ title, action, subtitle }: TopBarProps) {
  const { openMobile } = useSidebar();

  return (
    <header
      className={cn(
        'sticky top-0 z-20 bg-white border-b-2 border-hcl-border shadow-topbar',
        // Mobile-first padding; tightens on small screens so the title fits.
        'px-4 py-3 md:px-6 md:py-4',
        'flex items-center justify-between gap-3',
      )}
    >
      <div className="flex items-center gap-3 min-w-0">
        {/* Mobile hamburger — hidden on md+ where the rail is always visible */}
        <button
          type="button"
          onClick={openMobile}
          aria-label="Open navigation"
          className={cn(
            'md:hidden shrink-0 h-10 w-10 flex items-center justify-center rounded-lg',
            'text-hcl-navy hover:bg-hcl-light transition-colors motion-reduce:transition-none',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/60',
          )}
        >
          <Menu className="h-5 w-5" aria-hidden="true" />
        </button>

        <div className="w-1 h-6 rounded-full bg-hcl-blue shrink-0" aria-hidden="true" />

        <div className="min-w-0">
          <h1 className="text-lg md:text-xl font-semibold text-hcl-navy tracking-tight truncate">
            {title}
          </h1>
          {subtitle && (
            <div className="text-xs text-hcl-muted mt-0.5 truncate">{subtitle}</div>
          )}
        </div>
      </div>

      {action && <div className="shrink-0 flex items-center gap-2">{action}</div>}
    </header>
  );
}
