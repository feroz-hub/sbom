'use client';

import Link from 'next/link';
import { useAuth } from '@/hooks/useAuth';
import { NativePasswordSettings } from '@/components/auth/NativePasswordSettings';
import { ChevronRight, Sparkles } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';

/**
 * Settings index. Currently a single-section index (AI configuration);
 * future sections slot in as additional rows.
 *
 * The previous Phase 4 read-only ``AiSettings`` component has been
 * superseded by the editable ``AiSettingsPage`` at ``/settings/ai``.
 */
export default function SettingsPage() {
  const { hasPermission, user } = useAuth();
  const administration = [
    { title: 'Users & audit history', href: '/settings/native-users', visible: hasPermission('tenant:user:read') || hasPermission('platform:user:read') },
    { title: 'Roles, permissions & access management', href: '/settings/tenant', visible: hasPermission('tenant:user:read') },
    { title: 'Tenants', href: '/settings/platform/tenants', visible: hasPermission('platform:tenant:create') },
    { title: 'Authentication, delivery & operational health', href: '/settings/iam', visible: user?.isPlatformAdmin && hasPermission('platform:user:read') },
    { title: 'Platform administrators', href: '/settings/platform', visible: hasPermission('platform:administrator:read') },
  ].filter(item => item.visible);
  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Settings" />
      <main className="mx-auto w-full max-w-4xl space-y-4 px-6 py-6">
        <h1 className="text-xl font-semibold text-hcl-navy">Settings</h1>
        <NativePasswordSettings />
        {administration.length > 0 && <section className="space-y-3"><h2 className="text-lg font-semibold">Administration</h2><p>Manage people, tenant access and authentication operations.</p><ul className="grid gap-3 sm:grid-cols-2">{administration.map(item => <li key={item.href}><Link className="block rounded-lg border border-border-subtle p-4 font-medium hover:bg-surface-muted focus-visible:outline" href={item.href}>{item.title}</Link></li>)}</ul></section>}
        <ul className="space-y-2">
          <li>
            <Link
              href="/settings/ai"
              className="flex items-center justify-between rounded-lg border border-border-subtle bg-surface p-4 hover:bg-surface-muted"
            >
              <span className="flex items-center gap-3">
                <Sparkles className="h-5 w-5 text-primary" aria-hidden />
                <span>
                  <span className="block text-sm font-semibold text-hcl-navy">
                    AI configuration
                  </span>
                  <span className="block text-xs text-hcl-muted">
                    Providers · API keys · budget caps · kill switch
                  </span>
                </span>
              </span>
              <ChevronRight className="h-4 w-4 text-hcl-muted" aria-hidden />
            </Link>
          </li>
        </ul>
      </main>
    </div>
  );
}
