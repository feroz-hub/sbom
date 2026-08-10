import { SkeletonCard } from '@/components/ui/Spinner';

/** Route-level fallback while client segments load. */
export default function Loading() {
  return (
    <div className="flex flex-1 flex-col p-6">
      <div className="mb-6 h-10 max-w-md animate-pulse rounded-lg bg-surface-muted" aria-hidden />
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
      <div className="mt-6 h-64 animate-pulse rounded-xl bg-surface-muted/80" aria-hidden />
    </div>
  );
}
