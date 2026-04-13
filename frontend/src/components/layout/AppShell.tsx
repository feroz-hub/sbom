'use client';

import { Sidebar } from './Sidebar';
import { SidebarProvider, useSidebar } from './SidebarContext';
import { cn } from '@/lib/utils';

function Shell({ children }: { children: React.ReactNode }) {
  const { collapsed } = useSidebar();
  return (
    <div className="flex min-h-screen">
      {/* Skip link — WCAG 2.4.1 Bypass Blocks. First focusable element so
          keyboard users can jump past the nav on every page load. */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <Sidebar />

      <main
        id="main-content"
        tabIndex={-1}
        className={cn(
          'flex-1 flex flex-col min-h-screen w-full',
          'transition-[margin-left] duration-300 ease-in-out motion-reduce:transition-none',
          // Mobile: sidebar is overlay, no margin offset
          'ml-0',
          // Desktop: reserve space for the fixed sidebar rail
          collapsed ? 'md:ml-16' : 'md:ml-60',
          'focus-visible:outline-none',
        )}
      >
        <div className="mx-auto flex w-full max-w-[1600px] flex-1 flex-col min-h-0">
          {children}
        </div>
      </main>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider>
      <Shell>{children}</Shell>
    </SidebarProvider>
  );
}
