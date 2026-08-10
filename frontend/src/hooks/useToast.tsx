'use client';

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { X, CheckCircle, AlertCircle, Info, Loader2, TriangleAlert } from 'lucide-react';

export type ToastVariant = 'success' | 'error' | 'warning' | 'info' | 'loading';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastOptions {
  /** Stable id — allows updateToast / dismiss to target this toast. */
  id?: string;
  /** Auto-dismiss delay in ms. 0 = never auto-dismiss. Default: 4000. */
  duration?: number;
  /** Optional action button rendered inside the toast. */
  action?: ToastAction;
}

interface ToastItem {
  id: string;
  message: string;
  variant: ToastVariant;
  duration: number;
  action?: ToastAction;
}

interface ToastContextValue {
  /** Show a new toast. Returns the toast id for later updates. */
  showToast: (message: string, variant?: ToastVariant, options?: ToastOptions) => string;
  /** Update an existing toast in-place (variant, message, action, duration). */
  updateToast: (id: string, message: string, variant: ToastVariant, options?: Omit<ToastOptions, 'id'>) => void;
  /** Immediately remove a toast by id. */
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const DEFAULT_DURATION: Record<ToastVariant, number> = {
  success: 4000,
  error:   6000,
  warning: 6000,
  info:    4000,
  loading: 0,     // loading toasts never auto-dismiss
};

function notificationId(message: string, variant: ToastVariant): string {
  let hash = 0;
  const value = `${variant}:${message}`;
  for (let index = 0; index < value.length; index += 1) {
    hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0;
  }
  return `toast-${Math.abs(hash)}`;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback(
    (message: string, variant: ToastVariant = 'info', options?: ToastOptions): string => {
      const resolvedId = options?.id ?? notificationId(message, variant);
      const duration = options?.duration ?? DEFAULT_DURATION[variant];

      setToasts((prev) => {
        // Identical notifications from polling/SSE/mutation callbacks collapse
        // into the existing item instead of announcing the same result twice.
        const item: ToastItem = { id: resolvedId, message, variant, duration, action: options?.action };
        // Replace if id already exists (treat as update)
        const exists = prev.some((t) => t.id === resolvedId);
        return exists
          ? prev.map((t) => (t.id === resolvedId ? item : t))
          : [...prev, item];
      });
      return resolvedId;
    },
    [],
  );

  const updateToast = useCallback(
    (id: string, message: string, variant: ToastVariant, options?: Omit<ToastOptions, 'id'>) => {
      const duration = options?.duration ?? DEFAULT_DURATION[variant];
      setToasts((prev) =>
        prev.map((t) =>
          t.id === id ? { ...t, message, variant, duration, action: options?.action } : t,
        ),
      );
    },
    [],
  );

  return (
    <ToastContext.Provider value={{ showToast, updateToast, dismiss }}>
      {children}
      <ToastContainer toasts={toasts} dismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}

// ─── Container ───────────────────────────────────────────────────────────────

function ToastContainer({ toasts, dismiss }: { toasts: ToastItem[]; dismiss: (id: string) => void }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted || toasts.length === 0) return null;
  // Portal directly to body so transformed/animated application shells and
  // dialog stacking contexts can never clip or cover notifications.
  return createPortal(
    <div
      data-toast-container
      className="fixed top-4 right-4 z-[9999] flex w-80 max-w-[calc(100vw-2rem)] max-h-[calc(100dvh-2rem)] flex-col gap-2 overflow-y-auto"
    >
      {toasts.map((t) => (
        <ToastItemView key={t.id} toast={t} dismiss={dismiss} />
      ))}
    </div>,
    document.body,
  );
}

// ─── Single toast ─────────────────────────────────────────────────────────────

const variantStyles: Record<ToastVariant, { container: string; icon: ReactNode }> = {
  success: {
    container:
      'bg-surface border border-green-200 shadow-lg dark:border-emerald-800 dark:bg-surface-muted',
    icon: <CheckCircle className="h-5 w-5 shrink-0 text-green-500 dark:text-emerald-400" />,
  },
  error: {
    container: 'bg-surface border border-red-200 shadow-lg dark:border-red-800 dark:bg-surface-muted',
    icon: <AlertCircle className="h-5 w-5 shrink-0 text-red-500 dark:text-red-400" />,
  },
  warning: {
    container: 'bg-surface border border-amber-300 shadow-lg dark:border-amber-700 dark:bg-surface-muted',
    icon: <TriangleAlert className="h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />,
  },
  info: {
    container:
      'bg-surface border border-primary/25 shadow-lg dark:border-primary/40 dark:bg-surface-muted',
    icon: <Info className="h-5 w-5 shrink-0 text-primary" />,
  },
  loading: {
    container: 'bg-surface border border-border shadow-lg dark:bg-surface-muted',
    icon: <Loader2 className="h-5 w-5 shrink-0 animate-spin text-primary" />,
  },
};

function ToastItemView({ toast, dismiss }: { toast: ToastItem; dismiss: (id: string) => void }) {
  const { container, icon } = variantStyles[toast.variant];

  // Start the lifetime only after this toast has actually committed to the
  // browser DOM. Starting the timer in showToast can expire a notification
  // before its first paint when a mutation also triggers a costly route/query
  // refresh.
  useEffect(() => {
    if (toast.duration <= 0) return undefined;
    const timer = window.setTimeout(() => dismiss(toast.id), toast.duration);
    return () => window.clearTimeout(timer);
  }, [toast.id, toast.message, toast.variant, toast.duration, dismiss]);

  return (
    <div
      className={`flex items-start gap-3 p-4 rounded-lg ${container} animate-in slide-in-from-right duration-200`}
      role={toast.variant === 'error' || toast.variant === 'warning' ? 'alert' : 'status'}
      aria-live={toast.variant === 'error' || toast.variant === 'warning' ? 'assertive' : 'polite'}
    >
      {icon}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-foreground">{toast.message}</p>
        {toast.action && (
          <button
            onClick={() => { toast.action!.onClick(); dismiss(toast.id); }}
            className="mt-1.5 text-xs font-medium text-primary hover:underline"
          >
            {toast.action.label} →
          </button>
        )}
      </div>
      <button
        onClick={() => dismiss(toast.id)}
        className="shrink-0 text-hcl-muted transition-colors hover:text-foreground"
        aria-label="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
