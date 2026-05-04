'use client';

import Link from 'next/link';
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
  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Settings" />
      <main className="mx-auto w-full max-w-4xl space-y-4 px-6 py-6">
        <h1 className="text-xl font-semibold text-hcl-navy">Settings</h1>
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
