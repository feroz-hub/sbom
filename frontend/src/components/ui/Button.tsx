import { cn } from '@/lib/utils';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  loading?: boolean;
  loadingLabel?: string;
  /** Adds a subtle glow halo on hover/focus. Use sparingly on hero CTAs. */
  glow?: boolean;
  children: ReactNode;
}

const variantClasses: Record<string, string> = {
  primary:
    'bg-primary text-white hover:bg-hcl-dark active:bg-hcl-dark border-transparent shadow-elev-1',
  secondary:
    'bg-surface text-hcl-navy hover:bg-surface-muted active:bg-border-subtle/60 border-border',
  danger:
    'bg-red-600 text-white hover:bg-red-700 active:bg-red-800 border-transparent shadow-elev-1',
  ghost:
    'bg-transparent text-hcl-navy hover:bg-surface-muted active:bg-border-subtle/60 border-transparent',
  outline:
    'bg-transparent text-primary border-primary hover:bg-primary hover:text-white active:bg-hcl-dark active:text-white',
};

const glowVariantClasses: Record<string, string> = {
  primary: 'hover:shadow-glow-primary focus-visible:shadow-glow-primary',
  secondary: 'hover:shadow-glow-cyan focus-visible:shadow-glow-cyan',
  danger: 'hover:shadow-glow-critical focus-visible:shadow-glow-critical',
  ghost: 'hover:shadow-glow-cyan focus-visible:shadow-glow-cyan',
  outline: 'hover:shadow-glow-primary focus-visible:shadow-glow-primary',
};

const sizeClasses: Record<string, string> = {
  sm: 'h-8 min-w-[2rem] px-3 text-xs gap-1.5 rounded-md',
  md: 'h-10 min-w-[2.5rem] px-4 text-sm gap-2 rounded-lg',
  lg: 'h-11 min-w-[2.75rem] px-5 text-base gap-2 rounded-lg',
  icon: 'h-10 w-10 p-0 rounded-lg',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    loading = false,
    loadingLabel = 'Loading',
    glow = false,
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
        'group/btn inline-flex items-center justify-center font-medium border',
        'transition-[background-color,color,border-color,box-shadow,transform] duration-base ease-spring',
        'will-change-transform',
        'hover:-translate-y-px active:translate-y-0 active:scale-[0.97]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
        'focus-visible:ring-hcl-blue/50 focus-visible:ring-offset-background',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:active:translate-y-0 disabled:active:scale-100',
        'motion-reduce:transition-none motion-reduce:hover:translate-y-0 motion-reduce:active:translate-y-0 motion-reduce:active:scale-100',
        '[&_svg]:transition-transform [&_svg]:duration-base [&_svg]:ease-spring',
        'hover:[&_svg]:scale-110 motion-reduce:hover:[&_svg]:scale-100',
        variantClasses[variant],
        glow && glowVariantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    >
      {loading && (
        <>
          <svg
            className="h-4 w-4 shrink-0 animate-spin motion-reduce:animate-none"
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
