'use client';

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './Button';

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  /** Optional sticky footer rendered below the scrollable body. */
  footer?: ReactNode;
  /**
   * Desktop max-width (≥640px). On mobile the dialog is always a bottom
   * sheet and ignores this. Default: ``md`` (max-w-md).
   */
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  dismissOnBackdrop?: boolean;
  /** id of an element inside the dialog body that summarises its contents (WCAG 2.2 — pairs with aria-labelledby for screen-reader announcement). */
  describedBy?: string;
}

const maxWidthClasses: Record<string, string> = {
  sm: 'sm:max-w-sm',
  md: 'sm:max-w-md',
  lg: 'sm:max-w-lg',
  xl: 'sm:max-w-2xl',
  '2xl': 'sm:max-w-4xl',
};

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function getFocusable(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.hasAttribute('aria-hidden') && el.offsetParent !== null,
  );
}

export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  maxWidth = 'md',
  dismissOnBackdrop = true,
  describedBy,
}: DialogProps) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  // Scroll-shadow signal on the body. The header/footer cast a subtle
  // shadow when the body has hidden content above/below them. Driven by
  // ``data-scroll-state`` so the CSS lives next to each component.
  const [scrollState, setScrollState] = useState<'atTop' | 'atBottom' | 'middle' | 'both'>('both');

  const updateScrollState = useCallback(() => {
    const el = bodyRef.current;
    if (!el) return;
    const { scrollTop, scrollHeight, clientHeight } = el;
    const atTop = scrollTop <= 1;
    const atBottom = scrollTop + clientHeight >= scrollHeight - 1;
    setScrollState(atTop && atBottom ? 'both' : atTop ? 'atTop' : atBottom ? 'atBottom' : 'middle');
  }, []);

  useEffect(() => {
    if (!open) return;

    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === 'Tab' && panelRef.current) {
        const focusable = getFocusable(panelRef.current);
        if (focusable.length === 0) {
          e.preventDefault();
          panelRef.current.focus();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === first) {
          // first is now focused; nothing to do (RTL pattern handled below)
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  // Body lock + ``data-dialog-open`` flag. The flag lets surfaces outside
  // the dialog (toasts, the right-edge action rail when one exists) react
  // via plain CSS without a new context provider.
  useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
      document.body.dataset.dialogOpen = 'true';
    } else {
      document.body.style.overflow = '';
      delete document.body.dataset.dialogOpen;
    }
    return () => {
      document.body.style.overflow = '';
      delete document.body.dataset.dialogOpen;
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      previouslyFocused.current = (document.activeElement as HTMLElement) ?? null;
      const raf = requestAnimationFrame(() => {
        if (panelRef.current) {
          const focusable = getFocusable(panelRef.current);
          (focusable[0] ?? panelRef.current).focus();
          // Initial scroll state once the body has rendered.
          updateScrollState();
        }
      });
      return () => cancelAnimationFrame(raf);
    }
    if (previouslyFocused.current && previouslyFocused.current.isConnected) {
      previouslyFocused.current.focus();
    }
  }, [open, updateScrollState]);

  if (!open) return null;
  // SSR guard — ``'use client'`` keeps this off the server, but RTL and
  // any future SSR-of-client-component path would still execute the
  // render before mount; ``document`` is the only honest gate.
  if (typeof document === 'undefined') return null;

  // Render the overlay + panel via a Portal mounted directly on
  // ``document.body``. This is load-bearing — ``position: fixed`` does not
  // mean "viewport-relative" if any ancestor has an active ``transform`` /
  // ``filter`` / ``perspective`` (CSS containing-block rule). The findings
  // table is wrapped in a ``.motion-rise`` card whose entry animation
  // leaves ``transform: matrix(1,0,0,1,0,0)`` in the computed style; an
  // inline-rendered fixed overlay would be sized against that card
  // (~2,641 px tall) instead of the viewport (~954 px). The portal moves
  // us to a body-level subtree where no ancestor has a transform, so
  // ``inset-0`` finally means what it says.
  const dialogTree = (
    // Outer wrapper: bottom-anchored on mobile (items-end), centered on sm+.
    <div
      className="fixed inset-0 z-50 flex items-end justify-center sm:items-center sm:p-4"
      role="presentation"
    >
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm dialog-scrim-in motion-reduce:animate-none"
        onClick={dismissOnBackdrop ? onClose : undefined}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={cn(
          // Layout: three-region flex column. Outer panel clips, body scrolls.
          'relative flex w-full flex-col overflow-hidden border border-border bg-surface shadow-xl',
          'dialog-panel-in motion-reduce:animate-none',
          'focus-visible:outline-none',
          // Mobile: bottom sheet — full-width, 90dvh tall, only top corners rounded.
          'max-h-[90dvh] rounded-t-xl rounded-b-none',
          // Desktop: centered card — bounded width, dvh-aware max-height capped at 800px,
          // fully rounded.
          'sm:w-[min(92vw,720px)] sm:max-h-[min(calc(100dvh-4rem),800px)] sm:rounded-xl',
          // The maxWidth prop only applies on sm+ (mobile is full-width).
          maxWidthClasses[maxWidth],
        )}
      >
        {/* Sticky title bar — never scrolls. Casts a subtle shadow when
            content is hidden above the visible body. */}
        <div
          className={cn(
            'flex shrink-0 items-center justify-between border-b border-border bg-surface-muted/80 px-6 py-4 transition-shadow',
            scrollState !== 'atTop' && scrollState !== 'both' &&
              'shadow-[0_4px_8px_-6px_rgba(0,0,0,0.15)]',
          )}
        >
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="h-5 w-1 shrink-0 rounded-full bg-gradient-to-b from-hcl-blue to-hcl-cyan" />
            <h2 id={titleId} className="truncate text-lg font-semibold text-hcl-navy">
              {title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className={cn(
              'rounded-lg p-2 text-hcl-muted transition-colors hover:bg-border-subtle hover:text-hcl-navy',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
            )}
            aria-label="Close dialog"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        {/* Scrollable body — the only scroll region inside the dialog.
            ``overscroll-contain`` stops scroll-chaining into the locked
            page when content bottoms out. */}
        <div
          ref={bodyRef}
          data-scroll-state={scrollState}
          onScroll={updateScrollState}
          className="flex-1 overflow-y-auto overscroll-contain"
        >
          {children}
        </div>
        {/* Sticky footer — optional. Casts a subtle shadow when content
            is hidden below the visible body. */}
        {footer ? (
          <div
            className={cn(
              'shrink-0 border-t border-border bg-surface-muted/80 transition-shadow',
              scrollState !== 'atBottom' && scrollState !== 'both' &&
                'shadow-[0_-4px_8px_-6px_rgba(0,0,0,0.15)]',
            )}
          >
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );

  return createPortal(dialogTree, document.body);
}

export function DialogBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('px-6 py-4', className)}>{children}</div>;
}

export function DialogFooter({ children }: { children: ReactNode }) {
  // Self-styled — three legacy callers (ProjectModal / SbomUploadModal /
  // ScheduleEditor) render this *inside* ``children`` to keep the form's
  // submit button associated with the form. The new Dialog ``footer``
  // prop is the preferred path for sticky footers; this helper remains so
  // those forms don't need to migrate.
  return (
    <div className="flex items-center justify-end gap-3 border-t border-border bg-surface-muted/80 px-6 py-4">
      {children}
    </div>
  );
}

interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  loading?: boolean;
  variant?: 'danger' | 'primary';
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Delete',
  loading = false,
  variant = 'danger',
}: ConfirmDialogProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      maxWidth="sm"
      dismissOnBackdrop={!loading}
      footer={
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant={variant} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      }
    >
      <DialogBody>
        <p className="text-sm text-hcl-muted">{message}</p>
      </DialogBody>
    </Dialog>
  );
}
