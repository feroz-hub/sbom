'use client';

import { createContext, useContext } from 'react';
import { Menu, Search } from 'lucide-react';
import { useSidebar } from './SidebarContext';
import { openCommandPalette } from './CommandPalette';
import { UserMenu } from './UserMenu';
import { ThemeToggle } from '@/components/theme/ThemeToggle';

export const ApplicationHeaderContext = createContext(false);
export function useApplicationHeader() {
  return useContext(ApplicationHeaderContext);
}

/** Account controls belong to the authenticated shell, including pages without a TopBar. */
export function ApplicationHeader() {
  const { openMobile } = useSidebar();
  return (
    <header
      aria-label="Authenticated application header"
      className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-2 border-b border-border bg-surface/95 px-4 backdrop-blur-md md:px-6"
    >
      <div className="flex min-w-0 items-center gap-2">
        <button
          type="button"
          aria-label="Open navigation"
          onClick={openMobile}
          className="rounded-lg p-2 text-foreground hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue md:hidden"
        >
          <Menu className="h-5 w-5" aria-hidden />
        </button>
        <span className="truncate text-xs font-semibold tracking-wide text-foreground/70">
          SBOM Analyzer
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={openCommandPalette}
          aria-label="Open command palette"
          className="inline-flex h-9 items-center gap-2 rounded-lg border border-border px-2.5 text-xs text-foreground/70 hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue"
        >
          <Search className="h-4 w-4" aria-hidden />
          <span className="hidden sm:inline">Search</span>
        </button>
        <UserMenu />
        <ThemeToggle />
      </div>
    </header>
  );
}
