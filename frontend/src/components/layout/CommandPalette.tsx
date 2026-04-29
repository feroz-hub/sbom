'use client';

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  ArrowRight,
  BookOpen,
  CornerDownLeft,
  ExternalLink,
  FileText,
  FolderOpen,
  GitCompareArrows,
  Keyboard,
  LayoutDashboard,
  Moon,
  Search,
  ShieldAlert,
  Sparkles,
  Sun,
  Upload,
  X,
  type LucideIcon,
} from 'lucide-react';
import { useTheme } from '@/components/theme/ThemeProvider';
import { getRecentSboms, getRuns } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

// ─── Command model ───────────────────────────────────────────────────────────

type CommandGroupKey = 'nav' | 'actions' | 'sboms' | 'runs';

interface CommandItem {
  id: string;
  group: CommandGroupKey;
  title: string;
  subtitle?: string;
  hint?: string;
  Icon: LucideIcon;
  /** Tone class applied to the icon (defaults to muted). */
  iconTone?: string;
  /** Optional keywords for fuzzy match — joined with title/subtitle. */
  keywords?: string;
  /** Executed when the user activates the command. */
  run: () => void;
  /** Single-keypress shortcut hint, e.g. ['G', 'D'] for "g d". */
  shortcut?: string[];
}

const GROUP_LABELS: Record<CommandGroupKey, string> = {
  nav: 'Navigation',
  actions: 'Actions',
  sboms: 'Recent SBOMs',
  runs: 'Recent runs',
};

const GROUP_ORDER: CommandGroupKey[] = ['nav', 'actions', 'sboms', 'runs'];

// ─── Fuzzy substring scorer ──────────────────────────────────────────────────
//
// Cheap but effective: literal substring match wins; otherwise rank by ratio of
// matched characters in order. Returns 0 when no match — caller filters those.

function fuzzyScore(haystack: string, needle: string): number {
  if (!needle) return 1;
  const h = haystack.toLowerCase();
  const n = needle.toLowerCase();
  // Direct substring match — boost early matches.
  const idx = h.indexOf(n);
  if (idx >= 0) {
    return 100 - idx + n.length / 10;
  }
  // Sequential-character match (subsequence). Penalise gaps.
  let hi = 0;
  let matched = 0;
  for (const c of n) {
    const next = h.indexOf(c, hi);
    if (next < 0) return 0;
    matched++;
    hi = next + 1;
  }
  return 30 + (matched / n.length) * 30;
}

// ─── Hook: build the command list ────────────────────────────────────────────

function useCommands(query: string, isOpen: boolean, onClose: () => void): CommandItem[] {
  const router = useRouter();
  const { resolvedTheme, setTheme } = useTheme();

  // Recent SBOMs and runs — only fetch while palette is open.
  const sbomsQuery = useQuery({
    queryKey: ['palette-recent-sboms'],
    queryFn: ({ signal }) => getRecentSboms(8, signal),
    enabled: isOpen,
    staleTime: 30_000,
  });

  const runsQuery = useQuery({
    queryKey: ['palette-recent-runs'],
    queryFn: ({ signal }) => getRuns({ page: 1, page_size: 8 }, signal),
    enabled: isOpen,
    staleTime: 30_000,
  });

  const close = useCallback(() => onClose(), [onClose]);
  const goto = useCallback(
    (href: string) => {
      router.push(href);
      close();
    },
    [router, close],
  );

  // Static nav + actions.
  const staticCommands = useMemo<CommandItem[]>(() => {
    const isDark = resolvedTheme === 'dark';
    return [
      // Navigation
      {
        id: 'nav.dashboard',
        group: 'nav',
        title: 'Dashboard',
        subtitle: 'Risk pulse and live metrics',
        Icon: LayoutDashboard,
        iconTone: 'text-hcl-blue',
        keywords: 'home overview',
        run: () => goto('/'),
        shortcut: ['G', 'D'],
      },
      {
        id: 'nav.projects',
        group: 'nav',
        title: 'Projects',
        subtitle: 'Manage projects',
        Icon: FolderOpen,
        iconTone: 'text-hcl-blue',
        keywords: 'project',
        run: () => goto('/projects'),
        shortcut: ['G', 'P'],
      },
      {
        id: 'nav.sboms',
        group: 'nav',
        title: 'SBOMs',
        subtitle: 'Upload, list, and inspect SBOM files',
        Icon: FileText,
        iconTone: 'text-hcl-blue',
        keywords: 'sbom upload',
        run: () => goto('/sboms'),
        shortcut: ['G', 'S'],
      },
      {
        id: 'nav.runs',
        group: 'nav',
        title: 'Analysis runs',
        subtitle: 'Filter and export run history',
        Icon: Activity,
        iconTone: 'text-hcl-blue',
        keywords: 'run history',
        run: () => goto('/analysis?tab=runs'),
        shortcut: ['G', 'R'],
      },
      {
        id: 'nav.compare',
        group: 'nav',
        title: 'Compare runs',
        subtitle: 'Diff two analysis runs side by side',
        Icon: GitCompareArrows,
        iconTone: 'text-hcl-blue',
        keywords: 'diff compare',
        run: () => goto('/analysis/compare'),
      },
      {
        id: 'nav.consolidated',
        group: 'nav',
        title: 'Run consolidated analysis',
        subtitle: 'Live multi-source scan with per-source progress',
        Icon: Sparkles,
        iconTone: 'text-hcl-cyan',
        keywords: 'analyze nvd osv ghsa vulndb live stream',
        run: () => goto('/analysis?tab=consolidated'),
      },
      // Actions
      {
        id: 'action.upload',
        group: 'actions',
        title: 'Upload SBOM',
        subtitle: 'Open the SBOMs page to start an upload',
        Icon: Upload,
        iconTone: 'text-emerald-600 dark:text-emerald-400',
        keywords: 'add new file cyclonedx spdx',
        run: () => goto('/sboms'),
      },
      {
        id: 'action.failing-runs',
        group: 'actions',
        title: 'Show failing runs',
        subtitle: 'Filter analysis runs to FAIL',
        Icon: ShieldAlert,
        iconTone: 'text-red-600 dark:text-red-400',
        keywords: 'fail findings vulnerable critical',
        run: () => goto('/analysis?tab=runs&status=FAIL'),
      },
      {
        id: 'action.toggle-theme',
        group: 'actions',
        title: isDark ? 'Switch to light theme' : 'Switch to dark theme',
        subtitle: `Currently ${resolvedTheme}`,
        Icon: isDark ? Sun : Moon,
        iconTone: isDark ? 'text-amber-500' : 'text-indigo-500',
        keywords: 'dark mode light mode appearance',
        run: () => {
          setTheme(isDark ? 'light' : 'dark');
          close();
        },
      },
      {
        id: 'action.shortcuts',
        group: 'actions',
        title: 'Show keyboard shortcuts',
        subtitle: 'Press ? anywhere to open this list',
        Icon: Keyboard,
        iconTone: 'text-hcl-muted',
        keywords: 'help cheatsheet keys',
        run: () => {
          window.dispatchEvent(new CustomEvent('sbom:show-cheatsheet'));
          close();
        },
        shortcut: ['?'],
      },
      {
        id: 'action.api-docs',
        group: 'actions',
        title: 'Open API docs',
        subtitle: 'FastAPI Swagger UI in a new tab',
        Icon: BookOpen,
        iconTone: 'text-hcl-muted',
        keywords: 'swagger openapi backend',
        run: () => {
          const apiBase = (process.env.NEXT_PUBLIC_API_URL ?? '').replace(/\/+$/, '');
          window.open(`${apiBase}/docs`, '_blank', 'noopener,noreferrer');
          close();
        },
      },
    ];
  }, [goto, close, resolvedTheme, setTheme]);

  // Recent SBOMs.
  const sbomCommands = useMemo<CommandItem[]>(() => {
    const data = sbomsQuery.data ?? [];
    return data.map((s) => ({
      id: `sbom.${s.id}`,
      group: 'sboms' as const,
      title: s.sbom_name,
      subtitle: `Open SBOM #${s.id} · ${formatDate(s.created_on)}`,
      hint: '↵ Open',
      Icon: FileText,
      iconTone: 'text-hcl-blue',
      keywords: `sbom #${s.id}`,
      run: () => goto(`/sboms/${s.id}`),
    }));
  }, [sbomsQuery.data, goto]);

  // Recent runs.
  const runCommands = useMemo<CommandItem[]>(() => {
    const data = runsQuery.data ?? [];
    return data.slice(0, 8).map((r) => ({
      id: `run.${r.id}`,
      group: 'runs' as const,
      title: r.sbom_name ? `${r.sbom_name} — Run #${r.id}` : `Run #${r.id}`,
      subtitle: `${r.run_status} · ${(r.total_findings ?? 0).toLocaleString()} findings · ${formatDate(r.completed_on ?? r.started_on)}`,
      hint: '↵ Open',
      Icon: Activity,
      iconTone:
        r.run_status === 'FAIL'
          ? 'text-red-600 dark:text-red-400'
          : r.run_status === 'PASS'
            ? 'text-emerald-600 dark:text-emerald-400'
            : 'text-hcl-muted',
      keywords: `analysis ${r.run_status}`,
      run: () => goto(`/analysis/${r.id}`),
    }));
  }, [runsQuery.data, goto]);

  // Filter + score.
  const all = useMemo(
    () => [...staticCommands, ...sbomCommands, ...runCommands],
    [staticCommands, sbomCommands, runCommands],
  );

  return useMemo(() => {
    const trimmed = query.trim();
    if (!trimmed) return all;
    const scored = all
      .map((c) => {
        const haystack = `${c.title} ${c.subtitle ?? ''} ${c.keywords ?? ''}`;
        return { c, score: fuzzyScore(haystack, trimmed) };
      })
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score);
    return scored.map((x) => x.c);
  }, [all, query]);
}

// ─── Component ───────────────────────────────────────────────────────────────

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const titleId = useId();

  const close = useCallback(() => setOpen(false), []);

  // Listen for global keybindings (cmd+k) and cross-component "open palette" events.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (open && e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
      }
    };
    const onCustomOpen = () => setOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('sbom:open-palette', onCustomOpen);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('sbom:open-palette', onCustomOpen);
    };
  }, [open]);

  // Reset query + focus input on open.
  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const commands = useCommands(query, open, close);

  // Group the filtered commands while preserving the scored order.
  const grouped = useMemo(() => {
    const map = new Map<CommandGroupKey, CommandItem[]>();
    for (const c of commands) {
      const arr = map.get(c.group) ?? [];
      arr.push(c);
      map.set(c.group, arr);
    }
    // Build a flat array in display order so arrow keys traverse predictably.
    const flat: CommandItem[] = [];
    const sections: { key: CommandGroupKey; items: CommandItem[] }[] = [];
    for (const key of GROUP_ORDER) {
      const items = map.get(key);
      if (!items || items.length === 0) continue;
      sections.push({ key, items });
      flat.push(...items);
    }
    return { sections, flat };
  }, [commands]);

  // Keep activeIndex in bounds when filter changes.
  useEffect(() => {
    if (activeIndex >= grouped.flat.length) {
      setActiveIndex(0);
    }
  }, [grouped.flat.length, activeIndex]);

  // Scroll active item into view.
  useEffect(() => {
    if (!open) return;
    const list = listRef.current;
    if (!list) return;
    const items = list.querySelectorAll<HTMLElement>('[data-cmd-row]');
    items[activeIndex]?.scrollIntoView({ block: 'nearest', behavior: 'auto' });
  }, [activeIndex, open]);

  // Local key handling on the input (arrows + enter).
  const onInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => (i + 1) % Math.max(grouped.flat.length, 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex(
        (i) => (i - 1 + Math.max(grouped.flat.length, 1)) % Math.max(grouped.flat.length, 1),
      );
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActiveIndex(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setActiveIndex(Math.max(0, grouped.flat.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const item = grouped.flat[activeIndex];
      if (item) item.run();
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center p-4 pt-[12vh]"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <button
        type="button"
        className="absolute inset-0 bg-black/50 backdrop-blur-sm dialog-scrim-in"
        aria-label="Close command palette"
        onClick={close}
      />
      <div
        className={cn(
          'relative z-[101] w-full max-w-xl overflow-hidden rounded-2xl',
          'glass-strong shadow-elev-4 dialog-panel-in',
          'border-border-subtle',
        )}
      >
        {/* Search input */}
        <div className="flex items-center gap-2 border-b border-border-subtle px-3 py-3">
          <Search className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
          <input
            ref={inputRef}
            id={titleId}
            type="search"
            placeholder="Search pages, actions, SBOMs, runs…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={onInputKeyDown}
            className="min-w-0 flex-1 bg-transparent py-1 text-base text-hcl-navy placeholder:text-hcl-muted focus:outline-none"
            autoComplete="off"
            aria-label="Command palette search"
            aria-controls={`${titleId}-list`}
            aria-activedescendant={
              grouped.flat[activeIndex] ? `cmd-${grouped.flat[activeIndex].id}` : undefined
            }
          />
          <button
            type="button"
            onClick={close}
            className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-surface-muted hover:text-hcl-navy"
            aria-label="Close"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        {/* Result list */}
        <ul
          ref={listRef}
          id={`${titleId}-list`}
          role="listbox"
          aria-label="Search results"
          className="max-h-[min(60vh,440px)] overflow-y-auto py-1"
        >
          {grouped.flat.length === 0 ? (
            <li className="px-6 py-12 text-center">
              <Search className="mx-auto h-6 w-6 text-hcl-muted/60" aria-hidden />
              <p className="mt-3 text-sm font-medium text-hcl-navy">No matches</p>
              <p className="mt-1 text-xs text-hcl-muted">
                Try a shorter query, or jump to <kbd className="font-mono mx-0.5 rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] font-semibold">Dashboard</kbd>
              </p>
            </li>
          ) : (
            grouped.sections.map((section) => (
              <CommandSection
                key={section.key}
                groupKey={section.key}
                items={section.items}
                activeIndex={activeIndex}
                flatItems={grouped.flat}
                onActivate={(i) => setActiveIndex(i)}
                onRun={(item) => item.run()}
              />
            ))
          )}
        </ul>

        {/* Footer hint bar */}
        <div className="flex items-center justify-between gap-3 border-t border-border-subtle px-3 py-2 text-[11px] text-hcl-muted">
          <div className="flex items-center gap-3">
            <FooterKey label="↑↓" hint="Navigate" />
            <FooterKey label="↵" hint="Open" Icon={CornerDownLeft} />
            <FooterKey label="esc" hint="Close" />
          </div>
          <span className="hidden sm:flex items-center gap-1.5">
            <Sparkles className="h-3 w-3" aria-hidden />
            <span>{grouped.flat.length} {grouped.flat.length === 1 ? 'result' : 'results'}</span>
          </span>
        </div>
      </div>
    </div>
  );
}

// ─── Subcomponents ───────────────────────────────────────────────────────────

interface CommandSectionProps {
  groupKey: CommandGroupKey;
  items: CommandItem[];
  flatItems: CommandItem[];
  activeIndex: number;
  onActivate: (flatIndex: number) => void;
  onRun: (item: CommandItem) => void;
}

function CommandSection({
  groupKey,
  items,
  flatItems,
  activeIndex,
  onActivate,
  onRun,
}: CommandSectionProps) {
  return (
    <li className="px-2 pb-1.5 pt-2 first:pt-1">
      <p className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        {GROUP_LABELS[groupKey]}
      </p>
      <ul role="group">
        {items.map((item) => {
          const flatIndex = flatItems.indexOf(item);
          const isActive = flatIndex === activeIndex;
          return (
            <li key={item.id}>
              <button
                type="button"
                id={`cmd-${item.id}`}
                data-cmd-row
                role="option"
                aria-selected={isActive}
                onMouseEnter={() => onActivate(flatIndex)}
                onClick={() => onRun(item)}
                className={cn(
                  'group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors duration-fast',
                  isActive
                    ? 'bg-primary/10 text-hcl-navy'
                    : 'text-hcl-navy hover:bg-surface-muted',
                )}
              >
                <span
                  className={cn(
                    'flex h-8 w-8 shrink-0 items-center justify-center rounded-md ring-1 transition-colors',
                    isActive
                      ? 'bg-surface ring-primary/30'
                      : 'bg-surface-muted ring-border-subtle',
                  )}
                >
                  <item.Icon
                    className={cn('h-4 w-4', item.iconTone ?? 'text-hcl-muted')}
                    aria-hidden
                  />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium text-hcl-navy">
                    {item.title}
                  </span>
                  {item.subtitle && (
                    <span className="block truncate text-[11px] text-hcl-muted">
                      {item.subtitle}
                    </span>
                  )}
                </span>
                <span className="ml-auto flex shrink-0 items-center gap-1.5 text-[10px] text-hcl-muted">
                  {item.shortcut?.map((k, i) => (
                    <kbd
                      key={i}
                      className="font-mono rounded border border-border bg-surface px-1 py-0.5 text-[10px] font-semibold text-hcl-navy"
                    >
                      {k}
                    </kbd>
                  ))}
                  {!item.shortcut && isActive && (
                    <ArrowRight className="h-3 w-3 text-primary" aria-hidden />
                  )}
                  {item.id === 'action.api-docs' && (
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  )}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </li>
  );
}

interface FooterKeyProps {
  label: string;
  hint: string;
  Icon?: LucideIcon;
}

function FooterKey({ label, hint, Icon }: FooterKeyProps): ReactNode {
  return (
    <span className="inline-flex items-center gap-1">
      <kbd className="font-mono inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded border border-border bg-surface px-1 text-[10px] font-semibold text-hcl-navy">
        {Icon ? <Icon className="h-2.5 w-2.5" aria-hidden /> : label}
      </kbd>
      <span>{hint}</span>
    </span>
  );
}

// ─── Imperative API ──────────────────────────────────────────────────────────

/** Programmatically open the palette from anywhere (e.g. TopBar pill). */
export function openCommandPalette() {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent('sbom:open-palette'));
}
