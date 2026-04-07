'use client';

import { useEffect, useId, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './Button';

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl';
  /**
   * When true, clicking the backdrop closes the dialog. Default: true.
   * Disable for forms where data loss would be frustrating.
   */
  dismissOnBackdrop?: boolean;
}

const maxWidthClasses: Record<string, string> = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-2xl',
};

// ── Focus-trap helpers ───────────────────────────────────────────────────────
// Native <dialog> has focus trapping but it interferes with portaled content.
// This hand-rolled trap is small and framework-agnostic — Tab/Shift+Tab cycle
// inside the panel, never escaping to background DOM.
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
  maxWidth = 'md',
  dismissOnBackdrop = true,
}: DialogProps) {
  // Unique IDs per dialog instance — prevents aria collisions when multiple
  // dialogs exist in the DOM (e.g. confirm-delete over an edit dialog).
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  // ── Key handling: Escape to close, Tab to trap focus ──────────────────────
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
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  // ── Body scroll lock ──────────────────────────────────────────────────────
  useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  // ── Focus management ──────────────────────────────────────────────────────
  // On open: remember the caller's focused element, move focus into the panel.
  // On close: restore focus. Respects WCAG 2.4.3 Focus Order + 3.2.1 On Focus.
  useEffect(() => {
    if (open) {
      previouslyFocused.current = (document.activeElement as HTMLElement) ?? null;
      // Defer to give the panel a chance to mount before focusing.
      const raf = requestAnimationFrame(() => {
        if (panelRef.current) {
          const focusable = getFocusable(panelRef.current);
          (focusable[0] ?? panelRef.current).focus();
        }
      });
      return () => cancelAnimationFrame(raf);
    }
    // When closing, restore focus to the trigger.
    if (previouslyFocused.current && previouslyFocused.current.isConnected) {
      previouslyFocused.current.focus();
    }
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
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
        tabIndex={-1}
        className={cn(
          'relative w-full bg-white rounded-xl shadow-xl overflow-hidden',
          'dialog-panel-in motion-reduce:animate-none',
          'focus-visible:outline-none',
          maxWidthClasses[maxWidth],
        )}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b-2 border-hcl-border bg-hcl-light/40">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-1 h-5 rounded-full bg-hcl-blue shrink-0" />
            <h2 id={titleId} className="text-lg font-semibold text-hcl-navy truncate">
              {title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className={cn(
              'text-hcl-muted hover:text-hcl-navy transition-colors rounded-lg p-2',
              'hover:bg-hcl-border/40',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/60',
            )}
            aria-label="Close dialog"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="overflow-y-auto max-h-[calc(100vh-12rem)]">{children}</div>
      </div>
    </div>
  );
}

export function DialogBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('px-6 py-4', className)}>{children}</div>;
}

export function DialogFooter({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-hcl-border bg-hcl-light/40">
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
  /** "danger" (default — red) or "primary" — for destructive vs benign confirms. */
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
    <Dialog open={open} onClose={onClose} title={title} maxWidth="sm" dismissOnBackdrop={!loading}>
      <DialogBody>
        <p className="text-sm text-slate-600">{message}</p>
      </DialogBody>
      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant={variant} onClick={onConfirm} loading={loading}>
          {confirmLabel}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
