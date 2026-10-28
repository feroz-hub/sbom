import { cn } from '@/lib/utils';
import { type ElementType, type HTMLAttributes, type ReactNode } from 'react';

type MotionAs = 'div' | 'section' | 'article' | 'ul' | 'ol' | 'header' | 'main';

type MotionPreset = 'rise' | 'fade' | 'scale' | 'glide';

interface MotionProps extends HTMLAttributes<HTMLElement> {
  as?: MotionAs;
  preset?: MotionPreset;
  /** Delay in ms — useful for orchestrated entries when not using Stagger. */
  delay?: number;
  children: ReactNode;
}

const presetClasses: Record<MotionPreset, string> = {
  rise: 'motion-rise',
  fade: 'motion-fade-in',
  scale: 'motion-scale-in',
  glide: 'motion-glide',
};

/**
 * One-shot entry animation wrapper. Honors `prefers-reduced-motion` via the
 * underlying CSS keyframes (which are neutralized in the global media query).
 */
export function Motion({
  as: Component = 'div' as MotionAs,
  preset = 'rise',
  delay,
  className,
  style,
  children,
  ...props
}: MotionProps) {
  const Tag = Component as ElementType;
  return (
    <Tag
      className={cn(presetClasses[preset], className)}
      style={delay ? { ...style, animationDelay: `${delay}ms` } : style}
      {...props}
    >
      {children}
    </Tag>
  );
}

interface StaggerProps extends HTMLAttributes<HTMLElement> {
  as?: MotionAs;
  /** Cascade interval per child in ms. Default 60ms. */
  interval?: number;
  children: ReactNode;
}

/**
 * Cascading entry — each direct child gets a stepped delay.
 *
 * Default interval (60ms) is set in globals.css `.stagger > *:nth-child(...)`.
 * Pass a custom `interval` to override via inline style on each child.
 */
export function Stagger({
  as: Component = 'div' as MotionAs,
  interval,
  className,
  children,
  ...props
}: StaggerProps) {
  const Tag = Component as ElementType;
  if (interval == null) {
    return (
      <Tag className={cn('stagger', className)} {...props}>
        {children}
      </Tag>
    );
  }
  // Custom interval — wrap each child to inject animation-delay inline.
  const items = Array.isArray(children) ? children : [children];
  return (
    <Tag className={cn('stagger', className)} {...props}>
      {items.map((child, i) => (
        <div
          key={(child as { key?: string })?.key ?? i}
          style={{ animationDelay: `${i * interval}ms` }}
        >
          {child}
        </div>
      ))}
    </Tag>
  );
}
