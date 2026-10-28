import Link from 'next/link';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface BreadcrumbItem {
  label: string;
  /** Omit for the current page. */
  href?: string;
}

/** Shared navigation markup; pages and headers supply only the trail data. */
export function Breadcrumb({ items, className }: { items: BreadcrumbItem[]; className?: string }) {
  if (items.length === 0) return null;
  return (
    <nav aria-label="Breadcrumb" className={className}>
      <ol className="flex flex-wrap items-center gap-x-1 gap-y-0.5 text-xs text-hcl-muted">
        {items.map((item, index) => (
          <li key={`${item.label}-${index}`} className="flex min-w-0 items-center gap-1">
            {index > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 opacity-50" aria-hidden="true" />}
            {item.href ? (
              <Link href={item.href} className="max-w-[min(100vw-8rem,28rem)] truncate rounded px-0.5 font-medium text-hcl-muted transition-colors hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40">
                {item.label}
              </Link>
            ) : (
              <span aria-current={index === items.length - 1 ? 'page' : undefined} className={cn('max-w-[min(100vw-8rem,28rem)] truncate font-medium', index === items.length - 1 ? 'text-foreground' : 'text-hcl-muted')}>
                {item.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
