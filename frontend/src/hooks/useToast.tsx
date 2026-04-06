'use client';

import React, {
  createContext,
  useCallback,
  useContext,
  useState,
  useRef,
  type ReactNode,
} from 'react';
import { X, CheckCircle, AlertCircle, Info, Loader2 } from 'lucide-react';

export type ToastVariant = 'success' | 'error' | 'info' | 'loading';

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
  info:    4000,
  loading: 0,     // loading toasts never auto-dismiss
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  // Track auto-dismiss timers so we can clear them on update/dismiss
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    const t = timers.current.get(id);
    if (t) { clearTimeout(t); timers.current.delete(id); }
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const scheduleAutoDismiss = useCallback((id: string, duration: number) => {
    // Clear existing timer for this id
    const existing = timers.current.get(id);
    if (existing) clearTimeout(existing);
    if (duration <= 0) return;
    const t = setTimeout(() => dismiss(id), duration);
    timers.current.set(id, t);
  }, [dismiss]);

  const showToast = useCallback(
    (message: string, variant: ToastVariant = 'info', options?: ToastOptions): string => {
      const id = options?.id ?? Math.random().toString(36).slice(2);
      const duration = options?.duration ?? DEFAULT_DURATION[variant];

      const item: ToastItem = { id, message, variant, duration, action: options?.action };

      setToasts((prev) => {
        // Replace if id already exists (treat as update)
        const exists = prev.some((t) => t.id === id);
        return exists
          ? prev.map((t) => (t.id === id ? item : t))
          : [...prev, item];
      });
      scheduleAutoDismiss(id, duration);
      return id;
    },
    [scheduleAutoDismiss],
  );

  const updateToast = useCallback(
    (id: string, message: string, variant: ToastVariant, options?: Omit<ToastOptions, 'id'>) => {
      const duration = options?.duration ?? DEFAULT_DURATION[variant];
      setToasts((prev) =>
        prev.map((t) =>
          t.id === id ? { ...t, message, variant, duration, action: options?.action } : t,
        ),
      );
      scheduleAutoDismiss(id, duration);
    },
    [scheduleAutoDismiss],
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
  if (toasts.length === 0) return null;
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 w-80 max-h-[calc(100vh-2rem)] overflow-y-auto">
      {toasts.map((t) => (
        <ToastItemView key={t.id} toast={t} dismiss={dismiss} />
      ))}
    </div>
  );
}

// ─── Single toast ─────────────────────────────────────────────────────────────

const variantStyles: Record<ToastVariant, { container: string; icon: ReactNode }> = {
  success: {
    container: 'bg-white border border-green-200 shadow-lg',
    icon: <CheckCircle className="h-5 w-5 text-green-500 shrink-0" />,
  },
  error: {
    container: 'bg-white border border-red-200 shadow-lg',
    icon: <AlertCircle className="h-5 w-5 text-red-500 shrink-0" />,
  },
  info: {
    container: 'bg-white border border-blue-200 shadow-lg',
    icon: <Info className="h-5 w-5 text-blue-500 shrink-0" />,
  },
  loading: {
    container: 'bg-white border border-slate-200 shadow-lg',
    icon: <Loader2 className="h-5 w-5 text-hcl-blue shrink-0 animate-spin" />,
  },
};

function ToastItemView({ toast, dismiss }: { toast: ToastItem; dismiss: (id: string) => void }) {
  const { container, icon } = variantStyles[toast.variant];
  return (
    <div
      className={`flex items-start gap-3 p-4 rounded-lg ${container} animate-in slide-in-from-right duration-200`}
      role="alert"
    >
      {icon}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-gray-800">{toast.message}</p>
        {toast.action && (
          <button
            onClick={() => { toast.action!.onClick(); dismiss(toast.id); }}
            className="mt-1.5 text-xs font-medium text-hcl-blue hover:underline"
          >
            {toast.action.label} →
          </button>
        )}
      </div>
      <button
        onClick={() => dismiss(toast.id)}
        className="text-gray-400 hover:text-gray-600 transition-colors shrink-0"
        aria-label="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
