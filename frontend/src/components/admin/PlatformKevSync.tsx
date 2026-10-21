'use client';

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { usePermissions } from '@/hooks/usePermission';
import { useToast } from '@/hooks/useToast';
import { syncKevCatalog } from '@/lib/api';
import { PermissionButton } from '@/components/ui/PermissionButton';

/** KEV synchronization owns global data and requires current platform authority. */
export function PlatformKevSync() {
  const { isPlatformContext } = useAuth();
  const { can } = usePermissions();
  if (!isPlatformContext || !can('platform:admin')) return null;
  return <SyncAction />;
}

function SyncAction() {
  const qc = useQueryClient();
  const { showToast } = useToast();
  const sync = useMutation({
    mutationFn: () => syncKevCatalog(),
    onSuccess: async () => {
      await Promise.all(['kev-catalog', 'kev-filter-options', 'kev-detail'].map(key =>
        qc.invalidateQueries({ queryKey: [key] })));
      showToast('KEV catalog synced successfully', 'success');
    },
    onError: () => showToast('KEV catalog sync failed. Try again.', 'error'),
  });
  return <section aria-label="Global KEV catalog" className="rounded-xl border border-border bg-surface p-5 space-y-3">
    <h2 className="font-semibold">Global KEV catalog</h2>
    <p className="text-sm text-hcl-muted">Synchronize the shared CISA Known Exploited Vulnerabilities catalog for all tenants.</p>
    <PermissionButton permission="platform:admin" loading={sync.isPending} loadingLabel="Syncing KEV catalog" onClick={() => sync.mutate()}>Sync KEV Catalog</PermissionButton>
  </section>;
}
