import { cn } from '@/lib/utils';
import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, className, id, ...props }, ref) => {
    const reactId = useId();
    const inputId = id ?? `input-${reactId}`;
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
        <input
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={cn(
            'h-10 w-full rounded-lg border px-3 text-sm text-foreground placeholder:text-hcl-muted',
            'bg-surface transition-colors duration-150 motion-reduce:transition-none',
            'focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
            'disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-hcl-muted',
            error
              ? 'border-red-400 focus-visible:border-red-500 focus-visible:ring-red-300/40'
              : 'border-border hover:border-hcl-blue/40',
            className,
          )}
          {...props}
        />
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
Input.displayName = 'Input';

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, error, hint, className, id, ...props }, ref) => {
    const reactId = useId();
    const inputId = id ?? `textarea-${reactId}`;
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
        <textarea
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={cn(
            'min-h-[80px] w-full resize-y rounded-lg border px-3 py-2 text-sm text-foreground placeholder:text-hcl-muted',
            'bg-surface transition-colors duration-150 motion-reduce:transition-none',
            'focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
            'disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-hcl-muted',
            error
              ? 'border-red-400 focus-visible:border-red-500 focus-visible:ring-red-300/40'
              : 'border-border hover:border-hcl-blue/40',
            className,
          )}
          {...props}
        />
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
Textarea.displayName = 'Textarea';
