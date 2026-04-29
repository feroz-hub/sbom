'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-6 p-8">
      <div className="flex max-w-md flex-col items-center text-center">
        <AlertTriangle className="mb-2 h-12 w-12 text-amber-500" aria-hidden />
        <h1 className="text-lg font-semibold text-hcl-navy">Something went wrong</h1>
        <p className="mt-2 text-sm text-hcl-muted">
          {error.message || 'An unexpected error occurred in this part of the app.'}
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-3">
        <Button type="button" onClick={reset}>
          Try again
        </Button>
        <Link
          href="/"
          className={cn(
            'inline-flex h-10 items-center justify-center rounded-lg border border-border bg-surface px-4 text-sm font-medium text-hcl-navy',
            'transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
          )}
        >
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
