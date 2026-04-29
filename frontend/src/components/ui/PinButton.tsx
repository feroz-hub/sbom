'use client';

import { Star } from 'lucide-react';
import { usePinned, type PinnedKind } from '@/lib/pinned';
import { cn } from '@/lib/utils';

interface PinButtonProps {
  kind: PinnedKind;
  id: number;
  label: string;
  href: string;
  /** Compact mode for tight table rows — smaller hit target. */
  compact?: boolean;
  /** Hide unless the row is hovered or the item is already pinned. */
  hoverOnly?: boolean;
  className?: string;
}

/**
 * Toggleable pin icon. Star fills when pinned. Click stops event propagation
 * so it works inside row-level <Link>s without triggering navigation.
 */
export function PinButton({
  kind,
  id,
  label,
  href,
  compact = false,
  hoverOnly = false,
  className,
}: PinButtonProps) {
  const { isPinned, toggle } = usePinned(kind);
  const pinned = isPinned(id);

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    toggle({ id, label, href });
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-pressed={pinned}
      aria-label={pinned ? `Unpin ${label}` : `Pin ${label}`}
      title={pinned ? 'Unpin' : 'Pin to sidebar'}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-md transition-all duration-base ease-spring',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
        compact ? 'h-6 w-6' : 'h-7 w-7',
        pinned
          ? 'text-amber-500 hover:text-amber-600'
          : 'text-hcl-muted/60 hover:text-amber-500 hover:bg-surface-muted',
        hoverOnly && !pinned && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100',
        'motion-reduce:transition-none',
        className,
      )}
    >
      <Star
        className={cn(
          compact ? 'h-3.5 w-3.5' : 'h-4 w-4',
          'transition-transform duration-base ease-spring',
          pinned && 'scale-110 motion-reduce:scale-100',
        )}
        fill={pinned ? 'currentColor' : 'none'}
        aria-hidden
      />
    </button>
  );
}
