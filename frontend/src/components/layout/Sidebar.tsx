'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  CalendarClock,
  ChevronDown,
  ChevronLeft,
  FileText,
  FolderOpen,
  LayoutDashboard,
  Settings as SettingsIcon,
  Sparkles,
  Star,
  X,
  type LucideIcon,
} from 'lucide-react';
import { cn, formatDate } from '@/lib/utils';
import { useSidebar } from './SidebarContext';
import { SidebarStatus } from './SidebarStatus';
import { usePinned, unpin } from '@/lib/pinned';
import { getRecentSboms, getRuns } from '@/lib/api';

interface SubNavItem {
  href: string;
  label: string;
}

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Optional nested children — renders an expandable accordion. */
  children?: SubNavItem[];
}

const NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', icon: FolderOpen },
  { href: '/sboms', label: 'SBOMs', icon: FileText },
  {
    href: '/analysis',
    label: 'Analysis',
    icon: Activity,
    children: [
      { href: '/analysis?tab=runs', label: 'Runs' },
      { href: '/analysis?tab=consolidated', label: 'Consolidated' },
      { href: '/analysis/compare', label: 'Compare' },
    ],
  },
  { href: '/schedules', label: 'Schedules', icon: CalendarClock },
  {
    href: '/settings',
    label: 'Settings',
    icon: SettingsIcon,
    children: [
      { href: '/settings/ai', label: 'AI configuration' },
      { href: '/admin/ai-usage', label: 'AI usage' },
    ],
  },
];

function isActiveItem(item: NavItem, pathname: string): boolean {
  if (item.href === '/') return pathname === '/';
  if (item.href === '/analysis/compare') return pathname.startsWith('/analysis/compare');
  if (item.href === '/analysis') {
    return pathname.startsWith('/analysis') && !pathname.startsWith('/analysis/compare');
  }
  // Settings is the parent for both /settings/* and the AI cost dashboard
  // /admin/ai-usage — both are operator-side configuration surfaces.
  if (item.href === '/settings') {
    return pathname.startsWith('/settings') || pathname.startsWith('/admin/ai-usage');
  }
  return pathname.startsWith(item.href);
}

export function Sidebar() {
  const pathname = usePathname();
  const { collapsed, toggleCollapsed, mobileOpen, closeMobile } = useSidebar();

  // Auto-close drawer on navigation (mobile only).
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
          aria-hidden
        />
      )}

      <aside
        aria-label="Primary navigation"
        className={cn(
          'fixed left-0 top-0 z-40 flex h-screen flex-col bg-sidebar sidebar-rail',
          'border-r border-white/10 shadow-[4px_0_24px_rgba(0,0,0,0.12)] dark:border-white/10 dark:shadow-[4px_0_32px_rgba(0,0,0,0.45)]',
          'transition-all duration-300 ease-in-out motion-reduce:transition-none',
          'md:translate-x-0',
          collapsed ? 'md:w-16' : 'md:w-60',
          'w-60',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        {/* Brand bar — label slides + fades while the rail narrows; the logo
            block stays put so nothing jumps (px-4 ≈ centered in the 64px rail). */}
        <div className="flex shrink-0 items-center gap-3 border-b border-white/10 px-4 py-4 sidebar-brand-bar">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/20 bg-white/10 shadow-inner">
            <span className="text-xs font-bold leading-none tracking-tight text-white">HCL</span>
          </div>
          <div
            className={cn(
              'min-w-0 flex-1 overflow-hidden',
              'transition-[max-width,opacity] duration-300 ease-in-out motion-reduce:transition-none',
              collapsed ? 'max-w-full md:max-w-0 md:opacity-0' : 'max-w-full opacity-100',
            )}
          >
            <p className="truncate text-sm font-semibold leading-tight text-white">SBOM Analyzer</p>
            <p className="mt-0.5 truncate text-[11px] font-medium text-hcl-cyan">HCLTech Security</p>
          </div>
          <button
            type="button"
            onClick={closeMobile}
            aria-label="Close navigation"
            className={cn(
              'rounded-lg p-2 text-slate-100 transition-colors hover:bg-white/10 hover:text-white md:hidden',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
            )}
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>

        {/* Scrollable middle: nav + pinned + recent */}
        <div className="flex-1 overflow-y-auto">
          <nav className="space-y-0.5 px-2 py-3" aria-label="Main">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={`${item.href}-${item.label}`}
                item={item}
                pathname={pathname}
                collapsed={collapsed}
              />
            ))}
          </nav>

          {/* Pinned + Recent collapse smoothly via the grid-rows height trick
              (display:none can't animate; 0fr → 1fr can). */}
          <div
            className={cn(
              'grid transition-[grid-template-rows,opacity] duration-300 ease-in-out motion-reduce:transition-none',
              collapsed
                ? 'grid-rows-[1fr] md:grid-rows-[0fr] md:opacity-0'
                : 'grid-rows-[1fr] opacity-100',
            )}
          >
            <div className="min-h-0 overflow-hidden">
              <PinnedSection />
              <RecentSection />
            </div>
          </div>
        </div>

        {/* Footer: status + collapse toggle */}
        <div className="hidden shrink-0 border-t border-white/10 px-2 py-3 md:block space-y-2">
          {!collapsed && <SidebarStatus />}
          {collapsed && <SidebarStatus compact />}

          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            className={cn(
              'flex w-full items-center rounded-lg py-2 text-slate-200',
              'transition-colors hover:bg-white/10 hover:text-white motion-reduce:transition-none',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
              'px-3',
              collapsed && 'md:px-[15px]',
            )}
          >
            {/* One chevron that rotates instead of two swapped icons — the
                180° spin reads as the rail changing direction. */}
            <ChevronLeft
              className={cn(
                'h-[18px] w-[18px] shrink-0 transition-transform duration-300 ease-in-out motion-reduce:transition-none',
                collapsed && 'md:rotate-180',
              )}
              aria-hidden
            />
            <span
              className={cn(
                'truncate whitespace-nowrap text-xs font-medium overflow-hidden',
                'transition-[max-width,opacity,margin-left] duration-300 ease-in-out motion-reduce:transition-none',
                collapsed ? 'ml-3 max-w-[140px] md:ml-0 md:max-w-0 md:opacity-0' : 'ml-3 max-w-[140px] opacity-100',
              )}
            >
              Collapse
            </span>
          </button>
          {!collapsed && (
            <p className="truncate px-3 text-[10px] text-slate-300">© 2026 HCL Technologies</p>
          )}
        </div>
      </aside>
    </>
  );
}

// ─── NavLink with nested children ────────────────────────────────────────────

function NavLink({
  item,
  pathname,
  collapsed,
}: {
  item: NavItem;
  pathname: string;
  collapsed: boolean;
}) {
  const isActive = isActiveItem(item, pathname);
  const [expanded, setExpanded] = useState(isActive && !!item.children);

  // Auto-expand when route enters this section.
  useEffect(() => {
    if (isActive && item.children) setExpanded(true);
  }, [isActive, item.children]);

  const Icon = item.icon;

  if (item.children && item.children.length > 0) {
    return (
      <div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          aria-current={isActive && !expanded ? 'page' : undefined}
          aria-label={collapsed ? item.label : undefined}
          className={cn(
            'group relative flex w-full items-center rounded-lg text-sm font-medium',
            'transition-[padding,background-color,color] duration-300 ease-in-out motion-reduce:transition-none',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
            'px-3 py-2.5',
            collapsed && 'md:px-[15px]',
            isActive
              ? 'bg-hcl-violet text-white shadow-md shadow-black/15 ring-1 ring-white/10'
              : 'text-slate-100 hover:bg-white/10 hover:text-white',
          )}
        >
          <Icon
            className={cn(
              'h-[18px] w-[18px] shrink-0',
              isActive ? 'text-white' : 'text-slate-200 group-hover:text-white',
            )}
            aria-hidden
          />
          <span
            className={cn(
              'flex-1 truncate whitespace-nowrap text-left overflow-hidden',
              'transition-[max-width,opacity,margin-left] duration-300 ease-in-out motion-reduce:transition-none',
              collapsed ? 'ml-3 max-w-full md:ml-0 md:max-w-0 md:opacity-0' : 'ml-3 max-w-full opacity-100',
            )}
          >
            {item.label}
          </span>
          {!collapsed && (
            <ChevronDown
              className={cn(
                'h-3.5 w-3.5 shrink-0 text-slate-200 transition-transform duration-base',
                expanded && 'rotate-180',
              )}
              aria-hidden
            />
          )}
        </button>

        {/* Sub-nav height animates via grid-rows so it folds with the rail
            instead of popping in and out. */}
        <div
          className={cn(
            'grid transition-[grid-template-rows,opacity,visibility] duration-300 ease-in-out motion-reduce:transition-none',
            // `visibility` flips at the transition's end, so hidden links also
            // drop out of the tab order once the fold-up finishes.
            expanded && !collapsed
              ? 'visible grid-rows-[1fr] opacity-100'
              : 'invisible grid-rows-[0fr] opacity-0',
            expanded &&
              collapsed &&
              'visible grid-rows-[1fr] opacity-100 md:invisible md:grid-rows-[0fr] md:opacity-0',
          )}
        >
          <ul className="mt-0.5 ml-3 min-h-0 space-y-0.5 overflow-hidden border-l border-white/10 pl-3">
            {item.children.map((child) => {
              // Detect active child by pathname + query string approximation.
              const childActive =
                child.href === pathname ||
                (child.href.startsWith(pathname) && child.href.includes('?')) ||
                false;
              return (
                <li key={child.href}>
                  <Link
                    href={child.href}
                    aria-current={childActive ? 'page' : undefined}
                    className={cn(
                      'group flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors duration-150',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
                      childActive
                        ? 'bg-white/10 text-white'
                        : 'text-slate-200 hover:bg-white/5 hover:text-white',
                    )}
                  >
                    <span
                      aria-hidden
                      className={cn(
                        'inline-block h-1 w-1 shrink-0 rounded-full',
                        childActive ? 'bg-hcl-cyan' : 'bg-slate-500',
                      )}
                    />
                    {child.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    );
  }

  return (
    <Link
      href={item.href}
      aria-current={isActive ? 'page' : undefined}
      aria-label={collapsed ? item.label : undefined}
      className={cn(
        'group relative flex items-center rounded-lg text-sm font-medium',
        'transition-[padding,background-color,color] duration-300 ease-in-out motion-reduce:transition-none',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
        'px-3 py-2.5',
        collapsed && 'md:px-[15px]',
        isActive
          ? 'bg-hcl-blue text-white shadow-md shadow-black/15 ring-1 ring-white/10'
          : 'text-slate-100 hover:bg-white/10 hover:text-white',
      )}
    >
      <Icon
        className={cn(
          'h-[18px] w-[18px] shrink-0',
          isActive ? 'text-white' : 'text-slate-200 group-hover:text-white',
        )}
        aria-hidden
      />
      <span
        className={cn(
          'flex-1 truncate whitespace-nowrap overflow-hidden',
          'transition-[max-width,opacity,margin-left] duration-300 ease-in-out motion-reduce:transition-none',
          collapsed ? 'ml-3 max-w-full md:ml-0 md:max-w-0 md:opacity-0' : 'ml-3 max-w-full opacity-100',
        )}
      >
        {item.label}
      </span>
      {isActive && (
        <span
          className={cn(
            'ml-auto h-4 w-1 shrink-0 rounded-full bg-hcl-cyan shadow-[0_0_12px_rgba(0,178,226,0.6)]',
            'transition-opacity duration-300 ease-in-out motion-reduce:transition-none',
            collapsed && 'md:w-0 md:opacity-0',
          )}
          aria-hidden
        />
      )}
    </Link>
  );
}

// ─── Section: Pinned ─────────────────────────────────────────────────────────

function PinnedSection() {
  const sboms = usePinned('sbom');
  const runs = usePinned('run');
  const all = [
    ...sboms.items.map((i) => ({ ...i, kind: 'sbom' as const })),
    ...runs.items.map((i) => ({ ...i, kind: 'run' as const })),
  ].sort((a, b) => b.pinnedAt - a.pinnedAt);

  if (all.length === 0) return null;

  return (
    <SidebarSection title="Pinned" Icon={Star} iconClassName="text-amber-400">
      {all.slice(0, 8).map((item) => (
        <SidebarRow
          key={`${item.kind}-${item.id}`}
          href={item.href}
          label={item.label}
          subtitle={item.kind === 'sbom' ? 'SBOM' : 'Run'}
          onUnpin={() => unpin(item.kind, item.id)}
        />
      ))}
    </SidebarSection>
  );
}

// ─── Section: Recent ─────────────────────────────────────────────────────────

function RecentSection() {
  const sbomsQuery = useQuery({
    queryKey: ['sidebar-recent-sboms'],
    queryFn: ({ signal }) => getRecentSboms(3, signal),
    staleTime: 60_000,
  });

  const runsQuery = useQuery({
    queryKey: ['sidebar-recent-runs'],
    queryFn: ({ signal }) => getRuns({ page: 1, page_size: 3 }, signal),
    staleTime: 60_000,
  });

  const sboms = sbomsQuery.data ?? [];
  const runs = runsQuery.data ?? [];

  if (sboms.length === 0 && runs.length === 0) return null;

  return (
    <SidebarSection title="Recent" Icon={Sparkles} iconClassName="text-hcl-cyan">
      {sboms.map((s) => (
        <SidebarRow
          key={`sbom-${s.id}`}
          href={`/sboms/${s.id}`}
          label={s.sbom_name}
          subtitle={`SBOM · ${formatDate(s.created_on)}`}
        />
      ))}
      {runs.map((r) => (
        <SidebarRow
          key={`run-${r.id}`}
          href={`/analysis/${r.id}`}
          label={r.sbom_name ? `${r.sbom_name} · #${r.id}` : `Run #${r.id}`}
          subtitle={`Run · ${r.run_status}`}
        />
      ))}
    </SidebarSection>
  );
}

// ─── Reusable section + row ──────────────────────────────────────────────────

function SidebarSection({
  title,
  Icon,
  iconClassName,
  children,
}: {
  title: string;
  Icon: LucideIcon;
  iconClassName?: string;
  children: ReactNode;
}) {
  return (
    <section className="px-2 py-2 border-t border-white/5">
      <p className="flex items-center gap-1.5 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-200">
        <Icon className={cn('h-3 w-3', iconClassName)} aria-hidden />
        {title}
      </p>
      <ul className="space-y-0.5">{children}</ul>
    </section>
  );
}

function SidebarRow({
  href,
  label,
  subtitle,
  onUnpin,
}: {
  href: string;
  label: string;
  subtitle: string;
  onUnpin?: () => void;
}) {
  return (
    <li className="group/row">
      <Link
        href={href}
        title={label}
        className={cn(
          'flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs transition-colors duration-150',
          'text-slate-100 hover:bg-white/10 hover:text-white',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-cyan',
        )}
      >
        <span className="min-w-0 flex-1">
          <span className="block truncate font-medium">{label}</span>
          <span className="font-metric block truncate text-[10px] tabular-nums text-slate-300">
            {subtitle}
          </span>
        </span>
        {onUnpin && (
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onUnpin();
            }}
            aria-label={`Unpin ${label}`}
            title="Unpin"
            className={cn(
              'shrink-0 rounded p-0.5 text-slate-200 transition-all duration-base',
              'opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100',
              'hover:bg-white/15 hover:text-amber-300',
              'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-hcl-cyan',
            )}
          >
            <X className="h-3 w-3" aria-hidden />
          </button>
        )}
      </Link>
    </li>
  );
}
