'use client';

import { useState } from 'react';
import { useAiCredentialSettings } from '@/hooks/useAiCredentials';
import type { AiCredential } from '@/types/ai';
import { AddProviderDialog } from './AddProviderDialog';
import { BudgetCapsForm } from './BudgetCapsForm';
import { EditProviderDialog } from './EditProviderDialog';
import { ProvidersList } from './ProvidersList';
import { UsageSummary } from './UsageSummary';

/**
 * Phase 3 §3.1 container — three sections (providers / caps / usage)
 * stacked vertically with a kill-switch banner at the top when active.
 */
export function AiSettingsPage() {
  const { data: settings } = useAiCredentialSettings();
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<AiCredential | null>(null);

  return (
    <section className="space-y-6" aria-labelledby="ai-settings-page-heading">
      <h1
        id="ai-settings-page-heading"
        className="text-xl font-semibold text-hcl-navy"
      >
        AI Configuration
      </h1>

      {settings?.kill_switch_active ? (
        <div
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
        >
          <strong>AI features are disabled by kill switch.</strong> Re-enable in
          the Budget caps section below.
        </div>
      ) : null}

      <ProvidersList
        onAdd={() => setShowAdd(true)}
        onEdit={(c) => setEditing(c)}
      />

      <BudgetCapsForm />

      <UsageSummary />

      <AddProviderDialog open={showAdd} onClose={() => setShowAdd(false)} />
      <EditProviderDialog
        credential={editing}
        onClose={() => setEditing(null)}
      />
    </section>
  );
}
