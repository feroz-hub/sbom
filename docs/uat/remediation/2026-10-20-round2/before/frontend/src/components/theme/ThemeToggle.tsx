'use client';

import { Moon, Sun } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTheme } from './ThemeProvider';
import { cn } from '@/lib/utils';

export function ThemeToggle({ className }: { className?: string }) {
  const { resolvedTheme, toggleTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const isDark = resolvedTheme === 'dark';

  if (!mounted) {
    return (
      <div
        className={cn('inline-flex h-10 w-10 shrink-0 rounded-lg border border-transparent', className)}
        aria-hidden
      />
    );
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      className={cn(
        'inline-flex h-10 w-10 items-center justify-center rounded-lg border border-border',
        'bg-surface text-foreground shadow-sm transition-colors motion-reduce:transition-none',
        'hover:bg-surface-muted hover:border-border-subtle',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50 focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        className,
      )}
    >
      {isDark ? (
        <Sun className="h-5 w-5 text-amber-400" aria-hidden="true" />
      ) : (
        <Moon className="h-5 w-5 text-hcl-muted" aria-hidden="true" />
      )}
    </button>
  );
}
