'use client';

import React, {
  forwardRef,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type SelectHTMLAttributes,
} from 'react';
import { Check, ChevronDown, Search } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface SelectOptionItem {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  hint?: string;
  placeholder?: string;
  variant?: 'default' | 'filter';
  options?: SelectOptionItem[];
}

function extractOptions(children: React.ReactNode): SelectOptionItem[] {
  const options: SelectOptionItem[] = [];

  const traverse = (node: React.ReactNode) => {
    React.Children.forEach(node, (child) => {
      if (!React.isValidElement(child)) return;

      if (child.type === 'option') {
        const val = (child.props as { value?: unknown }).value !== undefined
          ? String((child.props as { value?: unknown }).value)
          : '';
        const rawChildren = (child.props as { children?: React.ReactNode }).children;
        const lbl = Array.isArray(rawChildren)
          ? rawChildren.join('')
          : typeof rawChildren === 'string'
            ? rawChildren
            : String(rawChildren ?? val);
        options.push({
          value: val,
          label: lbl,
          disabled: Boolean((child.props as { disabled?: boolean }).disabled),
        });
      } else if (child.props && (child.props as { children?: React.ReactNode }).children) {
        traverse((child.props as { children?: React.ReactNode }).children);
      }
    });
  };

  traverse(children);
  return options;
}

interface CustomFilterSelectProps extends Omit<SelectProps, 'variant' | 'options'> {
  inputId: string;
  errorId: string;
  hintId: string;
  describedBy?: string;
  providedOptions?: SelectOptionItem[];
}

const CustomFilterSelect = forwardRef<HTMLSelectElement, CustomFilterSelectProps>(
  (
    {
      inputId,
      errorId,
      hintId,
      describedBy,
      label,
      error,
      hint,
      placeholder,
      providedOptions,
      className,
      children,
      ...props
    },
    ref,
  ) => {
    const [isOpen, setIsOpen] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [highlightedIndex, setHighlightedIndex] = useState(-1);
    const [placement, setPlacement] = useState<'bottom' | 'top'>('bottom');

    const containerRef = useRef<HTMLDivElement>(null);
    const triggerRef = useRef<HTMLButtonElement>(null);
    const popupRef = useRef<HTMLDivElement>(null);
    const searchInputRef = useRef<HTMLInputElement>(null);
    const listboxId = `${inputId}-listbox`;

    const options = useMemo(() => {
      if (providedOptions && providedOptions.length > 0) {
        return providedOptions;
      }
      return extractOptions(children);
    }, [providedOptions, children]);

    const currentValue = props.value !== undefined ? String(props.value) : '';

    const selectedOption = useMemo(() => {
      return (
        options.find((opt) => opt.value === currentValue) ??
        (currentValue === '' ? options.find((opt) => opt.value === '') : undefined)
      );
    }, [options, currentValue]);

    const filteredOptions = useMemo(() => {
      if (!searchQuery.trim()) return options;
      const q = searchQuery.toLowerCase().trim();
      return options.filter((opt) => opt.label.toLowerCase().includes(q));
    }, [options, searchQuery]);

    // Flip popup above if space below is insufficient
    useEffect(() => {
      if (!isOpen || !triggerRef.current) return;
      const rect = triggerRef.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      const spaceAbove = rect.top;
      if (spaceBelow < 290 && spaceAbove > spaceBelow) {
        setPlacement('top');
      } else {
        setPlacement('bottom');
      }
    }, [isOpen]);

    // Close on outside click
    useEffect(() => {
      if (!isOpen) return;
      function handleClickOutside(e: MouseEvent) {
        if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
          setIsOpen(false);
          setSearchQuery('');
        }
      }
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [isOpen]);

    // Auto-focus search or sync highlight index on open
    useEffect(() => {
      if (isOpen) {
        const currentIdx = options.findIndex((opt) => opt.value === currentValue);
        setHighlightedIndex(currentIdx >= 0 ? currentIdx : 0);

        if (options.length >= 10) {
          setTimeout(() => {
            searchInputRef.current?.focus();
          }, 30);
        }
      } else {
        setSearchQuery('');
        setHighlightedIndex(-1);
      }
    }, [isOpen, currentValue, options]);

    // Scroll highlighted option into view
    useEffect(() => {
      if (highlightedIndex < 0 || !popupRef.current) return;
      const el = popupRef.current.querySelector(`#${listboxId}-opt-${highlightedIndex}`);
      if (el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ block: 'nearest' });
      }
    }, [highlightedIndex, listboxId]);

    const { name: propName, onChange: propOnChange } = props;

    const handleSelect = useCallback(
      (val: string) => {
        setIsOpen(false);
        setSearchQuery('');

        const syntheticEvent = {
          target: { value: val, name: propName, id: inputId },
          currentTarget: { value: val, name: propName, id: inputId },
        } as unknown as React.ChangeEvent<HTMLSelectElement>;

        propOnChange?.(syntheticEvent);
        triggerRef.current?.focus();
      },
      [propName, propOnChange, inputId],
    );

    const handleTriggerClick = () => {
      if (props.disabled) return;
      setIsOpen((prev) => !prev);
    };

    const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
      if (props.disabled) return;

      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
        } else {
          if (e.key === 'ArrowDown') {
            setHighlightedIndex((prev) => Math.min(prev + 1, filteredOptions.length - 1));
          } else if (e.key === 'ArrowUp') {
            setHighlightedIndex((prev) => Math.max(prev - 1, 0));
          } else if (e.key === 'Enter' || e.key === ' ') {
            if (highlightedIndex >= 0 && filteredOptions[highlightedIndex]) {
              handleSelect(filteredOptions[highlightedIndex].value);
            }
          }
        }
      } else if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        setIsOpen(false);
      }
    };

    const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setHighlightedIndex((prev) => Math.min(prev + 1, filteredOptions.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setHighlightedIndex((prev) => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (highlightedIndex >= 0 && filteredOptions[highlightedIndex]) {
          handleSelect(filteredOptions[highlightedIndex].value);
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        setIsOpen(false);
        triggerRef.current?.focus();
      }
    };

    const displayLabel = selectedOption
      ? selectedOption.label
      : placeholder || (options.length > 0 ? options[0].label : 'ALL');

    return (
      <div ref={containerRef} className="flex flex-col gap-1.5 relative">
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
          {/* Modern 2026 Enterprise Trigger Button */}
          <button
            type="button"
            id={`${inputId}-trigger`}
            ref={triggerRef}
            disabled={props.disabled}
            onClick={handleTriggerClick}
            onKeyDown={handleTriggerKeyDown}
            aria-haspopup="listbox"
            aria-expanded={isOpen}
            aria-controls={listboxId}
            aria-label={props['aria-label']}
            className={cn(
              'dashboard-filter-select-trigger flex h-10 w-full items-center justify-between gap-2 rounded-lg border px-3 text-sm text-left',
              'transition-colors duration-150 select-none',
              'focus:outline-none focus-visible:outline-none',
              props.disabled
                ? 'cursor-not-allowed'
                : undefined,
              error && 'border-red-400 focus:border-red-500 focus:ring-red-300/40',
              className,
            )}
          >
            <span className={cn('truncate flex-1', !selectedOption && 'text-[var(--select-text-muted)]')}>
              {displayLabel}
            </span>
            <ChevronDown
              className={cn(
                'h-4 w-4 shrink-0 transition-transform duration-200',
                isOpen && 'rotate-180',
                props.disabled ? 'text-[var(--select-text-muted)] opacity-60' : 'text-hcl-muted',
              )}
              aria-hidden="true"
            />
          </button>

          {/* Modern Open Dropdown Panel */}
          {isOpen && (
            <div
              ref={popupRef}
              className={cn(
                'absolute left-0 right-0 z-50 w-full',
                placement === 'top' ? 'bottom-full mb-1' : 'top-full mt-1',
                'rounded-[10px] border border-[var(--select-popup-border)]',
                'bg-[var(--select-popup-bg)]',
                'shadow-[var(--select-shadow)]',
                'p-1 flex flex-col',
                'animate-in fade-in duration-100',
              )}
            >
              {/* Optional Search for 10+ values */}
              {options.length >= 10 && (
                <div className="p-1 pb-1.5 border-b border-[var(--select-popup-border)] mb-1">
                  <div className="relative">
                    <Search
                      className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-hcl-muted"
                      aria-hidden="true"
                    />
                    <input
                      ref={searchInputRef}
                      type="search"
                      aria-label={`Search ${label || 'options'}`}
                      placeholder={`Search ${label ? label.toLowerCase() : 'options'}…`}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={handleSearchKeyDown}
                      className="w-full rounded-md border border-[var(--select-border)] bg-[var(--select-item-hover)] pl-8 pr-3 py-1.5 text-xs text-[var(--select-text)] placeholder:text-hcl-muted focus:border-hcl-blue focus:bg-[var(--select-bg)] focus:outline-none focus:ring-1 focus:ring-[var(--select-focus-ring)]"
                    />
                  </div>
                </div>
              )}

              {/* Options Listbox */}
              <div
                role="listbox"
                id={listboxId}
                aria-label={label}
                className="max-h-[280px] overflow-y-auto space-y-0.5"
              >
                {filteredOptions.length === 0 ? (
                  <div className="px-3 py-6 text-center text-xs text-hcl-muted">
                    No options matching &ldquo;{searchQuery}&rdquo;
                  </div>
                ) : (
                  filteredOptions.map((opt, idx) => {
                    const isSelected = opt.value === currentValue;
                    const isHighlighted = idx === highlightedIndex;

                    return (
                      <div
                        key={`${opt.value}-${idx}`}
                        id={`${listboxId}-opt-${idx}`}
                        role="option"
                        aria-selected={isSelected}
                        onClick={() => {
                          if (opt.disabled) return;
                          handleSelect(opt.value);
                        }}
                        onMouseEnter={() => setHighlightedIndex(idx)}
                        className={cn(
                          'flex min-h-[38px] w-full items-center justify-between rounded-md px-2.5 py-2 text-sm text-left',
                          'cursor-pointer transition-colors duration-100 select-none',
                          isSelected
                            ? 'bg-[var(--select-item-active)] text-hcl-blue font-medium'
                            : isHighlighted
                              ? 'bg-[var(--select-item-hover)] text-hcl-blue'
                              : 'text-[var(--select-text)] hover:bg-[var(--select-item-hover)]',
                          opt.disabled && 'cursor-not-allowed opacity-50',
                        )}
                      >
                        <span className="truncate flex-1">{opt.label}</span>
                        {isSelected && (
                          <Check
                            className="h-4 w-4 shrink-0 text-hcl-blue ml-2"
                            aria-hidden="true"
                          />
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* Visually hidden native select for complete form and test suite compatibility */}
          <select
            ref={ref}
            id={inputId}
            name={props.name}
            value={currentValue}
            disabled={props.disabled}
            onChange={props.onChange}
            tabIndex={-1}
            className="sr-only pointer-events-none absolute -z-10 opacity-0"
            aria-describedby={describedBy}
          >
            {children}
          </select>
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
CustomFilterSelect.displayName = 'CustomFilterSelect';

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      label,
      error,
      hint,
      className,
      id,
      placeholder,
      variant = 'default',
      options: providedOptions,
      children,
      ...props
    },
    ref,
  ) => {
    const reactId = useId();
    const inputId = id ?? `select-${reactId}`;
    const errorId = `${inputId}-error`;
    const hintId = `${inputId}-hint`;
    const describedBy =
      [error ? errorId : null, hint && !error ? hintId : null].filter(Boolean).join(' ') ||
      undefined;

    if (variant === 'filter') {
      return (
        <CustomFilterSelect
          ref={ref}
          inputId={inputId}
          errorId={errorId}
          hintId={hintId}
          describedBy={describedBy}
          label={label}
          error={error}
          hint={hint}
          placeholder={placeholder}
          providedOptions={providedOptions}
          className={className}
          {...props}
        >
          {children}
        </CustomFilterSelect>
      );
    }

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
            className={cn(
              'pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2',
              props.disabled ? 'text-[#94A3B8] dark:text-slate-500' : 'text-hcl-muted',
            )}
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
