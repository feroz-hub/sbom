'use client';

import { TopBar } from '@/components/layout/TopBar';
import { LifecycleProviderSettings } from '@/components/admin/LifecycleProviderSettings';
import { usePermission } from '@/hooks/usePermission';

export default function LifecycleProvidersAdminPage() {
  const canRead = usePermission('lifecycle:provider:read');

  return (
    <div className="flex flex-1 flex-col">
      <TopBar title="Lifecycle Providers" />
      <main className="mx-auto w-full max-w-7xl px-6 py-6">
        {canRead ? (
          <LifecycleProviderSettings />
        ) : (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm text-hcl-muted">
            Access denied.
          </div>
        )}
      </main>
    </div>
  );
}
