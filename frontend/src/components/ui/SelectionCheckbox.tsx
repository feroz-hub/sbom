'use client';

import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';

/**
 * Tri-state checkbox for row selection.
 *
 * ``state`` drives the visual + ``aria-checked``:
 *   - ``'all'``           → checked
 *   - ``'some'``          → indeterminate (HTML attribute, set imperatively)
 *   - ``'none'``          → unchecked
 *
 * Why a small dedicated component: the indeterminate property is not
 * a React-controllable attribute — it must be set on the underlying
 * DOM node via a ref effect. Centralising that here keeps the
 * findings-table render free of the mechanic.
 */
export interface SelectionCheckboxProps {
  state: 'all' | 'some' | 'none';
  onChange: (checked: boolean) => void;
  /** Accessible label. Required — there is no visible text. */
  label: string;
  className?: string;
  /**
   * When non-null, sets ``data-testid`` so tests can target the
   * specific checkbox without indexing into the DOM.
   */
  testId?: string;
  disabled?: boolean;
}

export function SelectionCheckbox({
  state,
  onChange,
  label,
  className,
  testId,
  disabled,
}: SelectionCheckboxProps) {
  const ref = useRef<HTMLInputElement | null>(null);

  // ``indeterminate`` is a runtime-only DOM property; React does not
  // pass it through props. Sync it after every render.
  useEffect(() => {
    if (ref.current) {
      ref.current.indeterminate = state === 'some';
    }
  }, [state]);

  const ariaChecked: 'true' | 'false' | 'mixed' =
    state === 'all' ? 'true' : state === 'some' ? 'mixed' : 'false';

  return (
    <input
      ref={ref}
      type="checkbox"
      checked={state === 'all'}
      onChange={(e) => onChange(e.target.checked)}
      aria-checked={ariaChecked}
      aria-label={label}
      data-testid={testId}
      disabled={disabled}
      className={cn(
        'h-4 w-4 cursor-pointer rounded border-border text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30 disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
    />
  );
}
