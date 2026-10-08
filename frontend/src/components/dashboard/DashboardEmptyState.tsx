'use client';

import Link from 'next/link';
import { FileUp } from 'lucide-react';
import { usePermissions } from '@/hooks/usePermission';

export function DashboardEmptyState({ filtered, onClear }: { filtered: boolean; onClear: () => void }) {
  const { can: hasPermission } = usePermissions();
  return (
    <section aria-label="Dashboard guidance" className="flex flex-wrap items-center gap-4 rounded-2xl border border-border bg-surface-muted p-5">
      <FileUp className="h-6 w-6 shrink-0 text-hcl-blue" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <h2 className="font-semibold text-hcl-navy">{filtered ? 'No data matches the current filters' : 'No SBOMs uploaded yet'}</h2>
        <p className="mt-1 text-sm text-hcl-muted">{filtered ? 'Change or clear your scope filters to see more inventory.' : 'Upload an SBOM to start component, vulnerability, lifecycle and VEX analysis.'}</p>
      </div>
      {filtered ? <button onClick={onClear} className="rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">Clear filters</button> : <div className="flex flex-wrap gap-3 text-sm">
        {hasPermission('project:create') && <Link className="rounded-lg px-3 py-2 text-hcl-blue hover:underline focus-visible:ring-2 focus-visible:ring-hcl-blue" href="/projects">Create project →</Link>}
        {hasPermission('sbom:upload') && <Link className="rounded-lg bg-hcl-blue px-4 py-2 font-medium text-white focus-visible:ring-2 focus-visible:ring-hcl-blue" href="/sboms?action=upload">Upload SBOM</Link>}
      </div>}
    </section>
  );
}
