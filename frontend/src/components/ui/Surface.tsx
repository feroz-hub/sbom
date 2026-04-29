import { cn } from '@/lib/utils';
import { forwardRef, type HTMLAttributes, type ReactNode } from 'react';

export type SurfaceVariant = 'solid' | 'inset' | 'elevated' | 'glass' | 'gradient';
export type SurfaceElevation = 0 | 1 | 2 | 3 | 4;

interface SurfaceProps extends HTMLAttributes<HTMLDivElement> {
  variant?: SurfaceVariant;
  elevation?: SurfaceElevation;
  interactive?: boolean;
  /** Adds a subtle accent bar on the left edge (HCL blue). */
  accent?: boolean;
  children: ReactNode;
}

const variantClasses: Record<SurfaceVariant, string> = {
  solid: 'bg-surface border border-border',
  inset: 'bg-surface-muted border border-border-subtle',
  elevated: 'bg-surface border border-border',
  glass: 'glass text-foreground',
  gradient: 'surface-gradient border border-border',
};

const elevationClasses: Record<SurfaceElevation, string> = {
  0: 'shadow-none',
  1: 'shadow-elev-1',
  2: 'shadow-elev-2',
  3: 'shadow-elev-3',
  4: 'shadow-elev-4',
};

/**
 * Layered surface primitive — successor to Card for richer compositions.
 *
 * - `solid`: standard opaque card
 * - `inset`: nested panel (flatter, muted bg)
 * - `elevated`: same as solid but with default shadow
 * - `glass`: backdrop-blurred translucent surface (use sparingly, only over interesting backgrounds)
 * - `gradient`: subtle radial gradient for hero/risk panels
 */
export const Surface = forwardRef<HTMLDivElement, SurfaceProps>(function Surface(
  {
    variant = 'solid',
    elevation = variant === 'elevated' ? 2 : 0,
    interactive = false,
    accent = false,
    className,
    children,
    ...props
  },
  ref,
) {
  return (
    <div
      ref={ref}
      className={cn(
        'rounded-xl transition-[box-shadow,transform,border-color] duration-base motion-reduce:transition-none',
        variantClasses[variant],
        elevationClasses[elevation],
        accent && 'card-accent',
        interactive &&
          'cursor-pointer hover:-translate-y-0.5 hover:shadow-elev-3 motion-reduce:hover:translate-y-0',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
});

interface SurfaceSectionProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
}

export function SurfaceHeader({ children, className, ...props }: SurfaceSectionProps) {
  return (
    <div
      className={cn('flex items-center justify-between border-b border-border-subtle px-6 py-4', className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function SurfaceContent({ children, className, ...props }: SurfaceSectionProps) {
  return (
    <div className={cn('px-6 py-5', className)} {...props}>
      {children}
    </div>
  );
}

export function SurfaceFooter({ children, className, ...props }: SurfaceSectionProps) {
  return (
    <div
      className={cn('flex items-center justify-end gap-2 border-t border-border-subtle px-6 py-3', className)}
      {...props}
    >
      {children}
    </div>
  );
}
