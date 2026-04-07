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
  { href: '/',         label: 'Dashboard',     icon: LayoutDashboard },
  { href: '/projects', label: 'Projects',      icon: FolderOpen },
  { href: '/sboms',    label: 'SBOMs',         icon: FileText },
  { href: '/analysis', label: 'Analysis Runs', icon: Activity },
];

export function Sidebar() {
  const pathname = usePathname();
  const { collapsed, toggleCollapsed, mobileOpen, closeMobile } = useSidebar();

  // Close the mobile drawer whenever the user navigates — without this, a tap
  // on a link leaves the overlay covering the new page.
  useEffect(() => {
    closeMobile();
    // We intentionally only watch pathname (closeMobile is stable via useCallback).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  return (
    <>
      {/* ── Mobile backdrop (only rendered when drawer open) ─────────── */}
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
          'fixed left-0 top-0 h-screen flex flex-col z-40 bg-sidebar',
          'transition-all duration-300 ease-in-out motion-reduce:transition-none',
          // Desktop: always visible, width depends on collapsed state
          'md:translate-x-0',
          collapsed ? 'md:w-16' : 'md:w-60',
          // Mobile: fixed width, toggled via translate
          'w-60',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        {/* ── Brand ────────────────────────────────────────── */}
        <div
          className={cn(
            'flex items-center border-b border-white/10 shrink-0',
            // Collapsed styling only applies on desktop
            collapsed ? 'md:justify-center md:py-4 md:px-0' : '',
            'gap-3 px-4 py-4',
          )}
        >
          <div className="shrink-0 flex items-center justify-center w-9 h-9 rounded-lg bg-white/10 border border-white/20">
            <span className="text-white font-bold text-xs tracking-tight leading-none">
              HCL
            </span>
          </div>

          <div className={cn('min-w-0 flex-1', collapsed && 'md:hidden')}>
            <p className="text-white font-semibold text-sm leading-tight truncate">
              SBOM Analyzer
            </p>
            <p className="text-[#00B2E2] text-[11px] font-medium truncate mt-0.5">
              HCLTech Security
            </p>
          </div>

          {/* Mobile close button — only visible below md */}
          <button
            type="button"
            onClick={closeMobile}
            aria-label="Close navigation"
            className={cn(
              'md:hidden text-slate-300 hover:text-white rounded-lg p-2',
              'hover:bg-white/10 transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
            )}
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        {/* ── Navigation ───────────────────────────────────── */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto" aria-label="Main">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive =
              href === '/' ? pathname === '/' : pathname.startsWith(href);
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
                  // Collapsed only applies on desktop
                  collapsed ? 'md:justify-center md:px-0 md:py-3' : '',
                  'gap-3 px-3 py-2.5',
                  isActive
                    ? 'bg-hcl-blue text-white shadow-sm'
                    : 'text-slate-300 hover:bg-white/10 hover:text-white',
                )}
              >
                <Icon
                  className={cn(
                    'shrink-0 h-[18px] w-[18px]',
                    isActive ? 'text-white' : 'text-slate-400 group-hover:text-white',
                  )}
                  aria-hidden="true"
                />
                <span className={cn('truncate', collapsed && 'md:hidden')}>{label}</span>

                {/* Active indicator bar — hidden on collapsed desktop */}
                {isActive && (
                  <span
                    className={cn(
                      'ml-auto w-1.5 h-4 rounded-full bg-hcl-cyan shrink-0',
                      collapsed && 'md:hidden',
                    )}
                    aria-hidden="true"
                  />
                )}
              </Link>
            );
          })}
        </nav>

        {/* ── Toggle (desktop only — mobile uses the X close button) ──── */}
        <div className="px-2 py-3 border-t border-white/10 shrink-0 hidden md:block">
          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            className={cn(
              'w-full flex items-center rounded-lg py-2 text-slate-400',
              'hover:bg-white/10 hover:text-white transition-colors motion-reduce:transition-none',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
              collapsed ? 'justify-center px-0' : 'gap-3 px-3',
            )}
          >
            {collapsed ? (
              <ChevronRight className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
            ) : (
              <>
                <ChevronLeft className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
                <span className="text-xs font-medium truncate">Collapse</span>
              </>
            )}
          </button>

          {!collapsed && (
            <p className="text-slate-600 text-[10px] mt-2 px-3 truncate">
              © 2025 HCL Technologies
            </p>
          )}
        </div>
      </aside>
    </>
  );
}
