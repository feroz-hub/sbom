'use client';

import { Skeleton, SkeletonText } from '@/components/ui/Spinner';

/**
 * Skeleton for the three modal sections.
 *
 * Sized to match the populated layout so the dialog doesn't shift when the
 * fetch resolves. The header (CVE ID + severity + chips) renders from row
 * data immediately and is NOT part of the skeleton.
 */
export function CveSkeleton() {
  return (
    <div aria-hidden className="animate-pulse">
      <section className="space-y-3 px-6 py-4">
        <Skeleton className="h-3 w-32" />
        <SkeletonText lines={4} />
        <Skeleton className="h-3 w-48" />
        <div className="flex gap-1.5">
          <Skeleton className="h-5 w-16 rounded" />
          <Skeleton className="h-5 w-20 rounded" />
        </div>
      </section>

      <section className="space-y-3 border-t border-border-subtle px-6 py-4">
        <Skeleton className="h-3 w-40" />
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Skeleton className="h-14 rounded-md" />
          <Skeleton className="h-14 rounded-md" />
          <Skeleton className="h-14 rounded-md" />
          <Skeleton className="h-14 rounded-md" />
        </div>
        <Skeleton className="h-4 w-3/4" />
      </section>

      <section className="space-y-3 border-t border-border-subtle px-6 py-4">
        <Skeleton className="h-3 w-32" />
        <Skeleton className="h-12 rounded-md" />
        <div className="flex gap-1.5">
          <Skeleton className="h-5 w-24 rounded-full" />
          <Skeleton className="h-5 w-20 rounded-full" />
          <Skeleton className="h-5 w-28 rounded-full" />
        </div>
      </section>
    </div>
  );
}
