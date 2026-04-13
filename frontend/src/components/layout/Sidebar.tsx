'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect } from 'react';
import {
  LayoutDashboard,
  FolderOpen,
  FileText,
  Activity,
  ChevronLeft,
  ChevronRight,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSidebar } from './SidebarContext';

const navItems = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', icon: FolderOpen },
  { href: '/sboms', label: 'SBOMs', icon: FileText },
  { href: '/analysis', label: 'Analysis Runs', icon: Activity },
];

export function Sidebar() {
  const pathname = usePathname();
  const { collapsed, toggleCollapsed, mobileOpen, closeMobile } = useSidebar();

  useEffect(() => {
    closeMobile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm md:hidden dialog-scrim-in motion-reduce:animate-none"
          onClick={closeMobile}
          aria-hidden="true"
        />
      )}

      <aside
        aria-label="Primary navigation"
        className={cn(
          'fixed left-0 top-0 z-40 flex h-screen flex-col bg-sidebar',
          'border-r border-white/5 shadow-[4px_0_24px_rgba(0,0,0,0.12)] dark:border-white/5 dark:shadow-[4px_0_32px_rgba(0,0,0,0.45)]',
          'transition-all duration-300 ease-in-out motion-reduce:transition-none',
          'md:translate-x-0',
          collapsed ? 'md:w-16' : 'md:w-60',
          'w-60',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        <div
          className={cn(
            'flex shrink-0 items-center border-b border-white/10 bg-gradient-to-r from-sidebar to-primary-900',
            collapsed ? 'md:justify-center md:px-0 md:py-4' : '',
            'gap-3 px-4 py-4',
          )}
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/20 bg-white/10 shadow-inner">
            <span className="text-xs font-bold leading-none tracking-tight text-white">HCL</span>
          </div>

          <div className={cn('min-w-0 flex-1', collapsed && 'md:hidden')}>
            <p className="truncate text-sm font-semibold leading-tight text-white">SBOM Analyzer</p>
            <p className="mt-0.5 truncate text-[11px] font-medium text-hcl-cyan">HCLTech Security</p>
          </div>

          <button
            type="button"
            onClick={closeMobile}
            aria-label="Close navigation"
            className={cn(
              'rounded-lg p-2 text-slate-300 transition-colors hover:bg-white/10 hover:text-white md:hidden',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
            )}
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3" aria-label="Main">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive = href === '/' ? pathname === '/' : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={isActive ? 'page' : undefined}
                aria-label={collapsed ? label : undefined}
                className={cn(
                  'group relative flex items-center rounded-lg text-sm font-medium',
                  'transition-colors duration-150 motion-reduce:transition-none',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
                  collapsed ? 'md:justify-center md:px-0 md:py-3' : '',
                  'gap-3 px-3 py-2.5',
                  isActive
                    ? 'bg-hcl-blue text-white shadow-md shadow-black/15 ring-1 ring-white/10'
                    : 'text-slate-300 hover:bg-white/10 hover:text-white',
                )}
              >
                <Icon
                  className={cn(
                    'h-[18px] w-[18px] shrink-0',
                    isActive ? 'text-white' : 'text-slate-400 group-hover:text-white',
                  )}
                  aria-hidden="true"
                />
                <span className={cn('truncate', collapsed && 'md:hidden')}>{label}</span>

                {isActive && (
                  <span
                    className={cn(
                      'ml-auto h-4 w-1 shrink-0 rounded-full bg-hcl-cyan shadow-[0_0_12px_rgba(0,178,226,0.6)]',
                      collapsed && 'md:hidden',
                    )}
                    aria-hidden="true"
                  />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="hidden shrink-0 border-t border-white/10 px-2 py-3 md:block">
          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            className={cn(
              'flex w-full items-center rounded-lg py-2 text-slate-400',
              'transition-colors hover:bg-white/10 hover:text-white motion-reduce:transition-none',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
              collapsed ? 'justify-center px-0' : 'gap-3 px-3',
            )}
          >
            {collapsed ? (
              <ChevronRight className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
            ) : (
              <>
                <ChevronLeft className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
                <span className="truncate text-xs font-medium">Collapse</span>
              </>
            )}
          </button>

          {!collapsed && (
            <p className="mt-2 truncate px-3 text-[10px] text-slate-500">© 2026 HCL Technologies</p>
          )}
        </div>
      </aside>
    </>
  );
}
