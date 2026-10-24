'use client';

import { useState } from 'react';
import { CveDetailDialog, type CveRowSeed } from '@/components/vulnerabilities/CveDetailDialog';
import type { CveSeverity } from '@/types/cve';
import type { FindingDiffRow } from '@/types/compare';
import { FindingRowAdvanced } from '../FindingRow/FindingRowAdvanced';

interface Props {
  rows: FindingDiffRow[];
  scanId?: number | null;
  scanName?: string | null;
}

function pickVisibleSeverity(row: FindingDiffRow): CveSeverity {
  if (row.change_kind === 'resolved') return row.severity_a ?? 'unknown';
  return row.severity_b ?? row.severity_a ?? 'unknown';
}

function rowToSeed(row: FindingDiffRow): CveRowSeed {
  // Map FindingDiffRow into the CveRowSeed shape the existing modal expects.
  // Compare's row schema doesn't carry CVSS score / vector — leave them
  // null so the modal's enriched fetch fills them in.
  const sev = pickVisibleSeverity(row).toUpperCase() as
    | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  return {
    vuln_id: row.vuln_id,
    severity: sev === 'NONE' as unknown as typeof sev ? 'UNKNOWN' : sev,
    score: null,
    cvss_version: null,
    in_kev: row.kev_current,
    epss: row.epss_current ?? 0,
    epss_percentile: row.epss_percentile_current,
    component_name: row.component_name,
    component_version: row.component_version_b ?? row.component_version_a,
    source: null,
  };
}

export function FindingsTable({ rows, scanId, scanName }: Props) {
  const [activeCve, setActiveCve] = useState<{ id: string; seed: CveRowSeed } | null>(null);

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border-subtle bg-surface-muted/40 px-6 py-10 text-center text-sm text-hcl-muted">
        No findings match the active filters.
      </div>
    );
  }

  return (
    <>
      <div className="overflow-x-auto rounded-lg border border-border-subtle">
        <table className="w-full table-auto text-sm">
          <thead className="bg-surface-muted text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            <tr>
              <th className="px-3 py-2 text-left">Change</th>
              <th className="px-3 py-2 text-left">CVE / Advisory</th>
              <th className="px-3 py-2 text-left">Severity</th>
              <th className="px-3 py-2 text-left">Component</th>
              <th className="px-3 py-2 text-left">Attribution</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <FindingRowAdvanced
                key={`${row.vuln_id}|${row.component_name}|${row.component_version_a ?? ''}|${row.component_version_b ?? ''}|${idx}`}
                row={row}
                onOpen={() => setActiveCve({ id: row.vuln_id, seed: rowToSeed(row) })}
              />
            ))}
          </tbody>
        </table>
      </div>
      <CveDetailDialog
        cveId={activeCve?.id ?? null}
        seed={activeCve?.seed ?? null}
        scanId={scanId ?? null}
        scanName={scanName ?? null}
        open={activeCve !== null}
        onOpenChange={(open) => {
          if (!open) setActiveCve(null);
        }}
        onSwitchCve={(newId) =>
          setActiveCve((prev) => (prev ? { id: newId, seed: prev.seed } : prev))
        }
      />
    </>
  );
}

