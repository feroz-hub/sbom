'use client';

import { useMemo, useState } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { Input } from '@/components/ui/Input';
import { exportFda510kSbomReport, HttpError } from '@/lib/api';
import { downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type {
  Fda510kIncompleteAnalysisDetail,
  Fda510kReportMetadata,
  SBOMSource,
} from '@/types';

interface Fda510kReportDialogProps {
  open: boolean;
  onClose: () => void;
  sboms: SBOMSource[];
}

const REQUIRED_FIELDS: Array<keyof Fda510kReportMetadata> = [
  'device_name',
  'manufacturer_sponsor',
  'device_software_version',
  'author_of_sbom_data',
  'prepared_by',
];

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function initialMetadata(sboms: SBOMSource[]): Fda510kReportMetadata {
  const first = sboms[0];
  const version = first?.productver || first?.product_version || first?.sbom_version || '';
  return {
    device_name: first?.product_name || first?.project_name || first?.sbom_name || '',
    device_model_catalog_number: '',
    manufacturer_sponsor: '',
    submission_type: '510(k)',
    submission_number: '',
    product_code_regulation_number: '',
    device_software_version: version,
    top_level_primary_component: first?.product_name || first?.sbom_name || '',
    author_of_sbom_data: first?.created_by || '',
    sbom_version: sboms.length === 1 ? first?.sbom_version || '' : '',
    sbom_formats_for_submission: 'CycloneDX / SPDX (machine-readable) + this workbook',
    sbom_generation_tool_and_version: '',
    primary_data_source: 'Persisted SBOM analysis results',
    prepared_by: first?.created_by || '',
    date_prepared: todayIso(),
    reviewed_approved_by: '',
    date_approved: '',
  };
}

function sameProjectId(sboms: SBOMSource[]): number | null {
  const ids = Array.from(new Set(sboms.map((sbom) => sbom.projectid ?? sbom.project_id ?? null)));
  return ids.length === 1 && ids[0] !== null ? ids[0] : null;
}

function blockerDetail(detail: unknown): Fda510kIncompleteAnalysisDetail | null {
  if (
    detail &&
    typeof detail === 'object' &&
    !Array.isArray(detail) &&
    (detail as { code?: string }).code === 'fda_510k_report_incomplete_analysis'
  ) {
    return detail as Fda510kIncompleteAnalysisDetail;
  }
  return null;
}

export function Fda510kReportDialog({ open, onClose, sboms }: Fda510kReportDialogProps) {
  const { showToast } = useToast();
  const [metadata, setMetadata] = useState<Fda510kReportMetadata>(() => initialMetadata(sboms));
  const [error, setError] = useState<string | null>(null);
  const [blockers, setBlockers] = useState<Fda510kIncompleteAnalysisDetail | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const projectId = useMemo(() => sameProjectId(sboms), [sboms]);
  const requiredMissing = REQUIRED_FIELDS.some((field) => !String(metadata[field] ?? '').trim());
  const canExport = projectId !== null && sboms.length > 0 && !requiredMissing && !submitting;

  const setField = (field: keyof Fda510kReportMetadata, value: string) => {
    setMetadata((current) => ({ ...current, [field]: value }));
  };

  const handleSubmit = async () => {
    if (!canExport || projectId === null) return;
    setSubmitting(true);
    setError(null);
    setBlockers(null);
    try {
      const { blob, filename } = await exportFda510kSbomReport(projectId, {
        selections: sboms.map((sbom) => ({ sbom_id: sbom.id })),
        metadata,
      });
      downloadBlob(blob, filename);
      showToast('FDA 510(k) SBOM report downloaded', 'success');
      onClose();
    } catch (err) {
      if (err instanceof HttpError) {
        const detail = blockerDetail(err.detail);
        if (detail) {
          setBlockers(detail);
          setError(null);
        } else {
          setError(err.message);
        }
      } else {
        setError(err instanceof Error ? err.message : 'Report export failed.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="FDA 510(k) SBOM Report"
      maxWidth="2xl"
      footer={
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} loading={submitting} disabled={!canExport}>
            Export workbook
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="rounded-lg border border-border bg-surface-muted/50 px-3 py-2 text-sm text-hcl-muted">
          {sboms.length} selected SBOM{sboms.length === 1 ? '' : 's'}
          {projectId === null ? ' across multiple or unassigned projects' : ''}
        </div>

        {projectId === null ? (
          <Alert variant="warning" title="Select SBOMs from one assigned project">
            The final workbook is generated at project scope.
          </Alert>
        ) : null}

        {error ? (
          <Alert variant="error" title="Export failed">
            {error}
          </Alert>
        ) : null}

        {blockers ? (
          <Alert variant="warning" title="Analysis is not complete">
            <ul className="space-y-1">
              {blockers.blockers.map((blocker) => (
                <li key={`${blocker.sbom_id}-${blocker.analysis_type}`}>
                  {blocker.sbom_name}: {blocker.analysis_type} is {blocker.status}
                </li>
              ))}
            </ul>
          </Alert>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <Input label="Device Name" required value={metadata.device_name} onChange={(e) => setField('device_name', e.target.value)} />
          <Input label="Manufacturer / Sponsor" required value={metadata.manufacturer_sponsor} onChange={(e) => setField('manufacturer_sponsor', e.target.value)} />
          <Input label="Device Software Version" required value={metadata.device_software_version} onChange={(e) => setField('device_software_version', e.target.value)} />
          <Input label="Author of SBOM Data" required value={metadata.author_of_sbom_data} onChange={(e) => setField('author_of_sbom_data', e.target.value)} />
          <Input label="Prepared By" required value={metadata.prepared_by} onChange={(e) => setField('prepared_by', e.target.value)} />
          <Input label="Date Prepared" type="date" value={metadata.date_prepared ?? ''} onChange={(e) => setField('date_prepared', e.target.value)} />
          <Input label="Device Model / Catalog Number" value={metadata.device_model_catalog_number ?? ''} onChange={(e) => setField('device_model_catalog_number', e.target.value)} />
          <Input label="Submission Type" value={metadata.submission_type ?? ''} onChange={(e) => setField('submission_type', e.target.value)} />
          <Input label="Submission Number" value={metadata.submission_number ?? ''} onChange={(e) => setField('submission_number', e.target.value)} />
          <Input label="Product Code / Regulation Number" value={metadata.product_code_regulation_number ?? ''} onChange={(e) => setField('product_code_regulation_number', e.target.value)} />
          <Input label="Top-Level / Primary Component" value={metadata.top_level_primary_component ?? ''} onChange={(e) => setField('top_level_primary_component', e.target.value)} />
          <Input label="SBOM Version" value={metadata.sbom_version ?? ''} onChange={(e) => setField('sbom_version', e.target.value)} />
          <Input label="SBOM Format(s) for Submission" value={metadata.sbom_formats_for_submission ?? ''} onChange={(e) => setField('sbom_formats_for_submission', e.target.value)} />
          <Input label="SBOM Generation Tool & Version" value={metadata.sbom_generation_tool_and_version ?? ''} onChange={(e) => setField('sbom_generation_tool_and_version', e.target.value)} />
          <Input label="Primary Data Source" value={metadata.primary_data_source ?? ''} onChange={(e) => setField('primary_data_source', e.target.value)} />
          <Input label="Reviewed / Approved By" value={metadata.reviewed_approved_by ?? ''} onChange={(e) => setField('reviewed_approved_by', e.target.value)} />
          <Input label="Date Approved" type="date" value={metadata.date_approved ?? ''} onChange={(e) => setField('date_approved', e.target.value)} />
        </div>
      </div>
    </Dialog>
  );
}
