'use client';

import { Surface, SurfaceContent } from '@/components/ui/Surface';
import { Skeleton, SkeletonText } from '@/components/ui/Spinner';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';

/**
 * Skeleton matching the rendered three-region shape so the user sees the
 * same affordances they'll get when data lands.
 */
export function CompareSkeleton() {
  return (
    <div className="space-y-4">
      <Surface variant="elevated">
        <SurfaceContent>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto_1fr_auto] lg:items-center">
            <div className="space-y-2">
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-9 w-full" />
            </div>
            <Skeleton className="h-5 w-5 rounded-full" />
            <div className="space-y-2 lg:items-end">
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-9 w-full" />
            </div>
            <Skeleton className="h-9 w-24" />
          </div>
        </SurfaceContent>
      </Surface>
      <Surface variant="elevated">
        <SurfaceContent>
          <Skeleton className="h-3 w-24" />
          <Skeleton className="mt-2 h-3 w-full" />
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="rounded-lg border border-border-subtle p-3">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="mt-2 h-7 w-32" />
                <Skeleton className="mt-1 h-3 w-16" />
              </div>
            ))}
          </div>
        </SurfaceContent>
      </Surface>
      <Surface variant="elevated">
        <SurfaceContent>
          <SkeletonText lines={6} />
        </SurfaceContent>
      </Surface>
    </div>
  );
}

export function EmptySelectionState() {
  return (
    <Surface variant="elevated">
      <SurfaceContent className="py-10">
        <EmptyState
          illustration="generic"
          title="Pick two runs to compare"
          description="Choose a baseline run (Run A) and a candidate run (Run B) using the pickers above. We'll show what changed — added, resolved, or reclassified — between them."
        />
      </SurfaceContent>
    </Surface>
  );
}

export function SameRunPickedState({ runId }: { runId: number }) {
  return (
    <Alert variant="info" title="That's the same run twice">
      Run #{runId} is selected on both sides — there's nothing to diff. Pick a
      different baseline or candidate to see changes.
    </Alert>
  );
}

export function RunNotReadyState({
  status,
  runId,
  onRetry,
}: {
  status?: string;
  runId?: number;
  onRetry?: () => void;
}) {
  const runLabel = runId != null ? `Run #${runId}` : 'One of the runs';
  const statusLabel = status ?? 'unknown';
  return (
    <Alert variant="warning" title={`${runLabel} isn't ready yet`}>
      <div className="flex flex-wrap items-center gap-3">
        <span>
          Status: <strong>{statusLabel}</strong>. Comparison will be available
          once the analysis finishes.
        </span>
        {onRetry && (
          <Button variant="secondary" onClick={onRetry} className="text-xs">
            Retry
          </Button>
        )}
      </div>
    </Alert>
  );
}

export function PermissionDeniedState() {
  return (
    <Alert variant="error" title="You don't have access to one of these runs">
      Ask the project owner to grant you access, or pick a different run.
    </Alert>
  );
}

export function RunNotFoundState({ runId }: { runId?: number }) {
  const idLabel = runId != null ? `Run #${runId}` : 'A run from this URL';
  return (
    <Alert variant="error" title="Run not found">
      {idLabel} no longer exists — it may have been deleted.
    </Alert>
  );
}

export function GenericCompareError({ message }: { message: string }) {
  return (
    <Alert variant="error" title="Could not compare runs">
      {message}
    </Alert>
  );
}
