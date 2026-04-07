import { cn } from '@/lib/utils';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  loading?: boolean;
  /**
   * When true, hides the loading spinner's label from assistive tech callers
   * (use when the button already conveys busy state in its parent container).
   */
  loadingLabel?: string;
  children: ReactNode;
}

const variantClasses: Record<string, string> = {
  primary:
    'bg-hcl-blue text-white hover:bg-hcl-dark active:bg-hcl-dark border-transparent shadow-sm',
  secondary:
    'bg-white text-hcl-navy hover:bg-hcl-light active:bg-hcl-border/40 border-hcl-border',
  danger:
    'bg-red-600 text-white hover:bg-red-700 active:bg-red-800 border-transparent shadow-sm',
  ghost:
    'bg-transparent text-hcl-navy hover:bg-hcl-light active:bg-hcl-border/40 border-transparent',
  outline:
    'bg-transparent text-hcl-blue border-hcl-blue hover:bg-hcl-blue hover:text-white active:bg-hcl-dark active:text-white',
};

// Fitts's law: minimum comfortable touch target is ~36-44px. `sm` stays tight
// for toolbars but raises to 32px, `md` hits 40px, `lg` hits 44px.
const sizeClasses: Record<string, string> = {
  sm:   'h-8 min-w-[2rem] px-3 text-xs gap-1.5 rounded-md',
  md:   'h-10 min-w-[2.5rem] px-4 text-sm gap-2 rounded-lg',
  lg:   'h-11 min-w-[2.75rem] px-5 text-base gap-2 rounded-lg',
  icon: 'h-10 w-10 p-0 rounded-lg', // square icon button, meets 40px target
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    loading = false,
    loadingLabel = 'Loading',
    children,
    className,
    disabled,
    type = 'button',
    ...props
  },
  ref,
) {
  const isDisabled = disabled || loading;
  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      aria-disabled={isDisabled || undefined}
      className={cn(
        'inline-flex items-center justify-center font-medium border',
        'transition-[background-color,color,border-color,box-shadow,transform] duration-150',
        'active:translate-y-px',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
        'focus-visible:ring-hcl-blue/60',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:active:translate-y-0',
        'motion-reduce:transition-none motion-reduce:active:translate-y-0',
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    >
      {loading && (
        <>
          <svg
            className="animate-spin motion-reduce:animate-none h-4 w-4 shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
          </svg>
          <span className="sr-only">{loadingLabel}</span>
        </>
      )}
      {children}
    </button>
  );
});
