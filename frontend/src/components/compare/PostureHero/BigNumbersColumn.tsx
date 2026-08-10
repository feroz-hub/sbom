'use client';

import { cn } from '@/lib/utils';

interface Props {
  added: number;
  resolved: number;
  severityChanged: number;
}

/**
 * Three semantic-coloured numerals stacked vertically on desktop, inline
 * on mobile. Numbers > 0 use the full hero-bignumber size; numbers === 0
 * recede to ~50% size and muted colour.
 *
 * No "net" / scalar sum (PB-1).
 *
 * Mobile (≤640px): renders inline pills via the parent's responsive
 * layout — this component is shape-agnostic; the parent supplies the
 * flex direction.
 */
export function BigNumbersColumn({ added, resolved, severityChanged }: Props) {
  return (
    <div
      className="flex flex-col gap-3 sm:gap-4"
      // The parent flips this to `flex-row gap-2 flex-wrap` on mobile via
      // the wrapper className.
    >
      <BigNumberRow value={added} label="added" tone="red" />
      <BigNumberRow value={resolved} label="resolved" tone="green" />
      <BigNumberRow value={severityChanged} label="severity" tone="amber" />
    </div>
  );
}

interface RowProps {
  value: number;
  label: string;
  tone: 'red' | 'green' | 'amber';
}

const TONE_CLASS: Record<RowProps['tone'], { active: string; muted: string }> = {
  red: {
    active: 'text-red-700 dark:text-red-300',
    muted: 'text-hcl-muted',
  },
  green: {
    active: 'text-emerald-700 dark:text-emerald-300',
    muted: 'text-hcl-muted',
  },
  amber: {
    active: 'text-amber-700 dark:text-amber-300',
    muted: 'text-hcl-muted',
  },
};

function BigNumberRow({ value, label, tone }: RowProps) {
  const isZero = value === 0;
  const colour = isZero ? TONE_CLASS[tone].muted : TONE_CLASS[tone].active;
  return (
    <div className="flex flex-col items-start sm:items-baseline">
      <span
        className={cn(
          'font-bold tabular-nums leading-none',
          colour,
          isZero ? 'opacity-60' : 'opacity-100',
        )}
        style={{
          fontSize: isZero ? 'clamp(1.5rem, 3vw, 2rem)' : 'var(--hero-bignumber-size)',
          letterSpacing: 'var(--hero-headline-tracking)',
        }}
        aria-label={`${value} ${label}`}
      >
        {value.toLocaleString()}
      </span>
      <span
        className={cn(
          'mt-1 text-[10px] font-semibold uppercase tracking-wider',
          isZero ? 'text-hcl-muted/60' : 'text-hcl-muted',
        )}
      >
        {label}
      </span>
    </div>
  );
}
