'use client';

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useRouter } from 'next/navigation';
import { Keyboard, X } from 'lucide-react';
import { cn } from '@/lib/utils';

// ─── Chord definitions ───────────────────────────────────────────────────────

interface ChordDef {
  prefix: string;
  key: string;
  label: string;
  /** Either a router path or an imperative action. */
  href?: string;
  action?: () => void;
}

const NAV_CHORDS: ChordDef[] = [
  { prefix: 'g', key: 'd', label: 'Dashboard', href: '/' },
  { prefix: 'g', key: 'p', label: 'Projects', href: '/projects' },
  { prefix: 'g', key: 's', label: 'SBOMs', href: '/sboms' },
  { prefix: 'g', key: 'r', label: 'Analysis runs', href: '/analysis?tab=runs' },
  { prefix: 'g', key: 'c', label: 'Compare runs', href: '/analysis/compare' },
  { prefix: 'g', key: 'a', label: 'Run consolidated analysis', href: '/analysis?tab=consolidated' },
];

const SINGLE_KEY_SHORTCUTS: Array<{ keys: string[]; label: string; hint: string }> = [
  { keys: ['⌘', 'K'], label: 'Open command palette', hint: 'Search anything' },
  { keys: ['Ctrl', 'K'], label: 'Open command palette (PC)', hint: 'Search anything' },
  { keys: ['?'], label: 'Show keyboard shortcuts', hint: 'This panel' },
  { keys: ['Esc'], label: 'Close current dialog', hint: '' },
];

const TABLE_SHORTCUTS: Array<{ keys: string[]; label: string }> = [
  { keys: ['↑', '↓'], label: 'Navigate result rows' },
  { keys: ['↵'], label: 'Open selected item' },
  { keys: ['Home', 'End'], label: 'Jump to first / last result' },
];

// Tags whose typing should suppress chord handling.
const TYPING_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);

function isTypingTarget(el: EventTarget | null): boolean {
  if (!el || !(el instanceof HTMLElement)) return false;
  if (TYPING_TAGS.has(el.tagName)) return true;
  if (el.isContentEditable) return true;
  // contenteditable=true on a parent; rare in our app but safe.
  let parent: HTMLElement | null = el.parentElement;
  while (parent) {
    if (parent.isContentEditable) return true;
    parent = parent.parentElement;
  }
  return false;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function KeyboardCheatsheet() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  const close = useCallback(() => setOpen(false), []);

  // Single global chord state — kept in a ref so the listener doesn't re-bind
  // every render. `null` means "no chord pending".
  const chordRef = useRef<{ prefix: string; until: number } | null>(null);

  const runChord = useCallback(
    (prefix: string, key: string) => {
      const def = NAV_CHORDS.find((c) => c.prefix === prefix && c.key === key);
      if (!def) return false;
      if (def.href) {
        router.push(def.href);
        return true;
      }
      def.action?.();
      return true;
    },
    [router],
  );

  // Global keydown listener — chord handling + ? to open + custom event.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Custom-event opener (from CommandPalette).
      // Handled in a separate effect below; here we only deal with raw keys.

      // While the cheatsheet is open, only handle Escape — let other keys pass.
      if (open) {
        if (e.key === 'Escape') {
          e.preventDefault();
          close();
        }
        return;
      }

      // Suppress when typing in an input/textarea.
      if (isTypingTarget(e.target)) return;
      // Suppress when modifier is held (chords are bare-key only).
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      const key = e.key.toLowerCase();

      // `?` → open cheatsheet. Some keyboards report `?` directly; others
      // report `/` with shift. Cover both.
      if (key === '?' || (e.shiftKey && key === '/')) {
        e.preventDefault();
        setOpen(true);
        chordRef.current = null;
        return;
      }

      // Chord handling: pending prefix?
      const now = Date.now();
      const pending = chordRef.current;
      if (pending && now < pending.until) {
        const consumed = runChord(pending.prefix, key);
        chordRef.current = null;
        if (consumed) e.preventDefault();
        return;
      }

      // Start a new chord if this is a known prefix.
      if (NAV_CHORDS.some((c) => c.prefix === key)) {
        chordRef.current = { prefix: key, until: now + 1500 };
        // Intentionally do NOT preventDefault — typing the prefix in a future
        // single-key shortcut should remain harmless if no follow-up arrives.
        return;
      }

      chordRef.current = null;
    };

    const onCustomShow = () => setOpen(true);

    window.addEventListener('keydown', onKey);
    window.addEventListener('sbom:show-cheatsheet', onCustomShow);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('sbom:show-cheatsheet', onCustomShow);
    };
  }, [open, close, runChord]);

  // Focus management when the modal opens/closes.
  useEffect(() => {
    if (open) {
      previouslyFocusedRef.current = document.activeElement as HTMLElement | null;
      requestAnimationFrame(() => {
        panelRef.current?.focus();
      });
    } else {
      previouslyFocusedRef.current?.focus();
    }
  }, [open]);

  if (!open) return null;

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-[101] flex items-start justify-center p-4 pt-[10vh]"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <button
        type="button"
        className="absolute inset-0 bg-black/50 backdrop-blur-sm dialog-scrim-in"
        aria-label="Close keyboard shortcuts"
        onClick={close}
      />
      <div
        ref={panelRef}
        tabIndex={-1}
        className={cn(
          'relative z-[102] w-full max-w-2xl overflow-hidden rounded-2xl',
          'glass-strong shadow-elev-4 dialog-panel-in',
          'border border-border-subtle',
        )}
      >
        <div className="flex items-center gap-3 border-b border-border-subtle px-5 py-4">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-hcl-light">
            <Keyboard className="h-4 w-4 text-hcl-blue" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="text-base font-semibold text-hcl-navy">
              Keyboard shortcuts
            </h2>
            <p className="text-xs text-hcl-muted">
              Press <Kbd>?</Kbd> anywhere to open this list. Single keys work outside text fields.
            </p>
          </div>
          <button
            type="button"
            onClick={close}
            className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-surface-muted hover:text-hcl-navy focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
            aria-label="Close"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <div className="grid grid-cols-1 gap-x-6 gap-y-5 p-5 sm:grid-cols-2 stagger">
          <Section title="General">
            {SINGLE_KEY_SHORTCUTS.map(({ keys, label, hint }) => (
              <Row key={`${label}-${keys.join('+')}`} keys={keys} label={label} hint={hint} />
            ))}
          </Section>

          <Section title="Navigation chords">
            <p className="-mt-1 mb-2 text-[11px] text-hcl-muted">
              Press <Kbd>g</Kbd> followed by a letter within 1.5s.
            </p>
            {NAV_CHORDS.map((c) => (
              <Row
                key={`${c.prefix}-${c.key}`}
                keys={[c.prefix.toUpperCase(), c.key.toUpperCase()]}
                label={c.label}
              />
            ))}
          </Section>

          <Section title="Inside lists / palette">
            {TABLE_SHORTCUTS.map(({ keys, label }) => (
              <Row key={`${label}-${keys.join('+')}`} keys={keys} label={label} />
            ))}
          </Section>

          <Section title="Findings table">
            <Row keys={['↑', '↓']} label="Navigate sorted rows" />
            <Row keys={['Click row chevron']} label="Expand for description / CWE / fix versions" />
            <Row keys={['Drag handle']} label="Adjust CVSS / EPSS range filters" />
          </Section>
        </div>

        <div className="flex items-center justify-between border-t border-border-subtle px-5 py-3 text-[11px] text-hcl-muted">
          <span className="inline-flex items-center gap-1.5">
            <Kbd>esc</Kbd>
            <span>to close</span>
          </span>
          <span>Got a shortcut idea? Let us know.</span>
        </div>
      </div>
    </div>
  );
}

// ─── Subcomponents ───────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
        {title}
      </h3>
      <ul className="space-y-1.5">{children}</ul>
    </section>
  );
}

function Row({ keys, label, hint }: { keys: string[]; label: string; hint?: string }) {
  return (
    <li className="flex items-center justify-between gap-3 rounded-lg px-2 py-1.5 hover:bg-surface-muted/60">
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm text-hcl-navy">{label}</p>
        {hint && <p className="truncate text-[11px] text-hcl-muted">{hint}</p>}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {keys.map((k, i) => (
          <Kbd key={i}>{k}</Kbd>
        ))}
      </div>
    </li>
  );
}

function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="font-mono inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded border border-border bg-surface px-1.5 text-[10px] font-semibold text-hcl-navy shadow-sm">
      {children}
    </kbd>
  );
}
