'use client';

import { useQuery } from '@tanstack/react-query';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Skeleton } from '@/components/ui/Spinner';
import { CveDetailDialog, type CveRowSeed } from '@/components/vulnerabilities/CveDetailDialog';
import { getVexInvestigation } from '@/lib/api';
import type { VexInvestigationRow, VexReconciliationStatus } from '@/types';
import { VexInvestigationPanel } from './VexInvestigationPanel';

const RECONCILIATION_EXPLANATIONS: Record<VexReconciliationStatus, string> = {
  ANALYZER_ONLY: 'The analyzer detected this vulnerability, but no applicable VEX statement is mapped to this component context.',
  VEX_ONLY: 'VEX evidence exists for this context without a corresponding analyzer detection. It does not create an analyzer finding.',
  MATCHED: 'The analyzer and VEX evidence share this component context. An internal decision takes precedence over imported statements.',
  CONFLICT_REVIEW_REQUIRED: 'Applicable VEX sources disagree. An analyst must review the evidence and record a decision.',
  REVALIDATION_REQUIRED: 'VEX reports a fix, but the analyzer still detects the vulnerability. The fix needs revalidation.',
  UNRESOLVED_MAPPING: 'The VEX assertion has not been confidently mapped to a component. Resolve the mapping before recording a component-specific decision.',
};

export function VexInvestigationDialog({ row, initialTab, onClose, onSaved, onConflict }: {
  row: VexInvestigationRow | null;
  initialTab: 'details' | 'investigation';
  onClose: () => void;
  onSaved: () => void;
  onConflict: () => void;
}) {
  const query = useQuery({
    queryKey: ['vex-investigation', row?.id ?? null],
    queryFn: ({ signal }) => getVexInvestigation(row!.id, signal),
    enabled: row !== null,
  });
  const detail = query.data;
  const componentId = detail?.component.component_id ?? null;
  const unresolved = detail ? componentId === null || detail.reconciliation_status === 'UNRESOLVED_MAPPING' : row?.component_id == null;
  const seed: CveRowSeed | null = row ? {
    vuln_id: row.canonical_vulnerability_id,
    cve_aliases: detail?.vulnerability.aliases ?? row.aliases,
    severity: detail?.vulnerability.severity ?? row.severity,
    score: detail?.vulnerability.cvss_score ?? null,
    cvss_version: null,
    in_kev: false,
    epss: null,
    epss_percentile: null,
    component_name: detail ? detail.component.name : row.component_name,
    component_version: detail ? detail.component.version : row.component_version,
    source: detail?.analyzer_evidence.sources.join(', ') || row.analyzer_sources.join(', '),
  } : null;
  const reconciliation = detail?.reconciliation_status ?? row?.reconciliation_status;
  const context = row ? [
    ['SBOM', detail?.sbom_name ?? row.sbom_name],
    ['Component', unresolved ? 'Unresolved' : `${seed?.component_name ?? 'Unknown'}${seed?.component_version ? ` ${seed.component_version}` : ''}`],
    ['Project', detail?.project_name ?? row.project_name],
    ['Application', detail?.product_name ?? row.product_name],
    ['Analyzer finding', detail?.analyzer_evidence.detection_state ?? row.analyzer_detection_state],
    ['Native VEX', detail ? detail.imported_vex.filter(statement => statement.source_format !== 'manual').map(statement => statement.source_status).filter(Boolean).join(', ') || 'No VEX statement' : row.native_vex_status ?? 'No VEX statement'],
    ['Effective status', detail?.effective_status ?? row.effective_status],
    ['Reconciliation', reconciliation?.replace(/_/g, ' ')],
    ['PURL', detail?.component.purl],
    ['CPE', detail?.component.cpe],
    ['BOM reference', detail?.component.bom_ref],
  ] : [];

  return <CveDetailDialog
    cveId={row?.canonical_vulnerability_id ?? null}
    seed={seed}
    open={row !== null}
    onOpenChange={(open) => { if (!open) onClose(); }}
    // Never use the scan's arbitrary first matching component for unresolved rows.
    scanId={unresolved ? null : detail?.analyzer_evidence.analysis_run_id ?? null}
    componentId={unresolved ? null : componentId}
    detailsEnabled={!query.isPending || query.isError}
    scanName={detail?.sbom_name ?? row?.sbom_name}
    initialTab={initialTab}
    contextPanel={row ? <section aria-label="Selected investigation context" className="space-y-3 border-b border-border px-6 py-3">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
        {context.filter(([, value]) => value != null && value !== '').map(([label, value]) => <div key={label} className="min-w-0">
          <dt className="font-medium text-hcl-muted">{label}</dt>
          <dd className="break-words">{value}</dd>
        </div>)}
      </dl>
      {reconciliation ? <p className="text-xs text-hcl-muted">{RECONCILIATION_EXPLANATIONS[reconciliation]}</p> : null}
      {unresolved ? <Alert variant="warning">Component mapping unresolved. No component-specific VEX decision can be saved until the mapping is resolved.</Alert> : null}
    </section> : null}
    investigationPanel={query.isPending ? <div role="status" aria-label="Loading investigation">
      <p className="text-sm text-hcl-muted">Loading investigation...</p>
      <Skeleton className="mt-3 h-40 w-full" />
    </div> : query.isError ? <Alert variant="error">
      Unable to load investigation details.
      <Button variant="ghost" onClick={() => void query.refetch()}>Retry investigation</Button>
    </Alert> : detail ? <VexInvestigationPanel
      key={detail.id}
      detail={detail}
      onSaved={onSaved}
      onConflict={() => { void query.refetch(); onConflict(); }}
    /> : null}
  />;
}
