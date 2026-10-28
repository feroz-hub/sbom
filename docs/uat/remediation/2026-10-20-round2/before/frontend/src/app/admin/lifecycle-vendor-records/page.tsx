'use client';

import { TopBar } from '@/components/layout/TopBar';
import { LifecycleVendorRecordsPage } from '@/components/admin/LifecycleVendorRecordsPage';
import { usePermission } from '@/hooks/usePermission';

export default function LifecycleVendorRecordsAdminPage() {
  const canRead = usePermission('lifecycle:vendor-record:read');

  return (
    <div className="flex flex-1 flex-col">
      <TopBar title="Lifecycle Vendor Records" />
      <main className="mx-auto w-full max-w-7xl px-6 py-6">
        {canRead ? (
          <LifecycleVendorRecordsPage />
        ) : (
          <div className="rounded-lg border border-border bg-surface p-5 text-sm text-hcl-muted">
            Access denied.
          </div>
        )}
      </main>
    </div>
  );
}
