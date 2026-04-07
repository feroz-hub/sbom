import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  /**
   * When true, adds a subtle hover lift (translateY + shadow) for clickable
   * cards. Respects prefers-reduced-motion.
   */
  interactive?: boolean;
}

export function Card({ children, className, interactive = false }: CardProps) {
  return (
    <div
      className={cn(
        'bg-white rounded-xl border border-hcl-border shadow-card',
        'transition-[box-shadow,transform] duration-200 motion-reduce:transition-none',
        interactive &&
          'hover:shadow-card-hover hover:-translate-y-0.5 motion-reduce:hover:translate-y-0 cursor-pointer',
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className }: CardProps) {
  return (
    <div className={cn('px-6 py-4 border-b border-hcl-border', className)}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className }: CardProps) {
  return (
    <h3 className={cn('text-base font-semibold text-hcl-navy', className)}>
      {children}
    </h3>
  );
}

export function CardContent({ children, className }: CardProps) {
  return (
    <div className={cn('px-6 py-4', className)}>
      {children}
    </div>
  );
}
