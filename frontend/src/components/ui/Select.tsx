import { cn } from '@/lib/utils';
import { forwardRef, useId, type SelectHTMLAttributes } from 'react';
import { ChevronDown } from 'lucide-react';

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  hint?: string;
  placeholder?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, hint, className, id, placeholder, children, ...props }, ref) => {
    const reactId = useId();
    const inputId = id ?? `select-${reactId}`;
    const errorId = `${inputId}-error`;
    const hintId = `${inputId}-hint`;
    const describedBy =
      [error ? errorId : null, hint && !error ? hintId : null].filter(Boolean).join(' ') ||
      undefined;

    return (
      <div className="flex flex-col gap-1.5">
        {label && (
          <label htmlFor={inputId} className="text-sm font-medium text-hcl-navy">
            {label}
            {props.required && (
              <span className="ml-1 text-red-500" aria-hidden="true">
                *
              </span>
            )}
          </label>
        )}
        <div className="relative">
          <select
            ref={ref}
            id={inputId}
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
            className={cn(
              'h-10 w-full appearance-none rounded-lg border px-3 pr-9 text-sm text-foreground',
              'bg-surface transition-colors duration-150 motion-reduce:transition-none',
              'focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
              'disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-hcl-muted',
              error
                ? 'border-red-400 focus-visible:border-red-500 focus-visible:ring-red-300/40'
                : 'border-border hover:border-hcl-blue/40',
              className,
            )}
            {...props}
          >
            {placeholder && (
              <option value="" disabled>
                {placeholder}
              </option>
            )}
            {children}
          </select>
          <ChevronDown
            className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted"
            aria-hidden="true"
          />
        </div>
        {error ? (
          <p id={errorId} className="text-xs text-red-600 dark:text-red-400" role="alert">
            {error}
          </p>
        ) : hint ? (
          <p id={hintId} className="text-xs text-hcl-muted">
            {hint}
          </p>
        ) : null}
      </div>
    );
  },
);
Select.displayName = 'Select';
