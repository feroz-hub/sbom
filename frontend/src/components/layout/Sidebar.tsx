'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  FolderOpen,
  FileText,
  Activity,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSidebar } from './SidebarContext';

const navItems = [
  { href: '/',         label: 'Dashboard',     icon: LayoutDashboard },
  { href: '/projects', label: 'Projects',       icon: FolderOpen },
  { href: '/sboms',    label: 'SBOMs',          icon: FileText },
  { href: '/analysis', label: 'Analysis Runs',  icon: Activity },
];

export function Sidebar() {
  const pathname  = usePathname();
  const { collapsed, toggle } = useSidebar();

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-screen flex flex-col z-30',
        'bg-sidebar transition-all duration-300 ease-in-out',
        collapsed ? 'w-16' : 'w-60'
      )}
    >
      {/* ── Brand ────────────────────────────────────────── */}
      <div
        className={cn(
          'flex items-center border-b border-white/10 shrink-0',
          collapsed ? 'justify-center py-4 px-0' : 'gap-3 px-4 py-4'
        )}
      >
        {/* HCLTech logo mark */}
        <div className="shrink-0 flex items-center justify-center w-9 h-9 rounded-lg bg-white/10 border border-white/20">
          <span className="text-white font-bold text-xs tracking-tight leading-none">
            HCL
          </span>
        </div>

        {!collapsed && (
          <div className="min-w-0">
            <p className="text-white font-semibold text-sm leading-tight truncate">
              SBOM Analyzer
            </p>
            <p className="text-[#00B2E2] text-[11px] font-medium truncate mt-0.5">
              HCLTech Security
            </p>
          </div>
        )}
      </div>

      {/* ── Navigation ───────────────────────────────────── */}
      <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-hidden">
        {navItems.map(({ href, label, icon: Icon }) => {
          const isActive =
            href === '/' ? pathname === '/' : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              title={collapsed ? label : undefined}
              className={cn(
                'flex items-center rounded-lg text-sm font-medium transition-all duration-150',
                collapsed ? 'justify-center px-0 py-3' : 'gap-3 px-3 py-2.5',
                isActive
                  ? 'bg-hcl-blue text-white shadow-sm'
                  : 'text-slate-300 hover:bg-white/10 hover:text-white'
              )}
            >
              <Icon
                className={cn(
                  'shrink-0 h-[18px] w-[18px]',
                  isActive ? 'text-white' : 'text-slate-400 group-hover:text-white'
                )}
              />
              {!collapsed && <span className="truncate">{label}</span>}

              {/* Active indicator bar */}
              {isActive && !collapsed && (
                <span className="ml-auto w-1.5 h-4 rounded-full bg-hcl-cyan shrink-0" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* ── Toggle ───────────────────────────────────────── */}
      <div className="px-2 py-3 border-t border-white/10 shrink-0">
        <button
          onClick={toggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={cn(
            'w-full flex items-center rounded-lg py-2 text-slate-400',
            'hover:bg-white/10 hover:text-white transition-colors',
            collapsed ? 'justify-center px-0' : 'gap-3 px-3'
          )}
        >
          {collapsed ? (
            <ChevronRight className="h-[18px] w-[18px] shrink-0" />
          ) : (
            <>
              <ChevronLeft className="h-[18px] w-[18px] shrink-0" />
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
  );
}
