'use client';

import Link from 'next/link';
import { AlertTriangle, ArrowRightLeft, CheckCircle2, Download, FileJson, Loader2, XCircle } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import {
  convertSbomToCycloneDX,
  exportSbomDocument,
  getSbom,
  getSbomConversionReport,
} from '@/lib/api';
import { invalidateSbomConversionSurfaces } from '@/lib/queryInvalidation';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import type { SBOMSource, SbomConversionReport } from '@/types';

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function isTimeoutError(err: unknown): boolean {
  return err instanceof Error && /timed out/i.test(err.message);
}

interface SbomConversionCardProps {
  sbom: SBOMSource;
  formatLabel?: string;
}

export function SbomConversionCard({ sbom, formatLabel }: SbomConversionCardProps) {
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [message, setMessage] = useState<string | null>(null);
  const [showReport, setShowReport] = useState(false);
  const [convertedId, setConvertedId] = useState<number | null>(sbom.converted_sbom_id ?? null);
  const [enrichmentStatus, setEnrichmentStatus] = useState<string | null>(
    sbom.enrichment_status ?? null,
  );

  const isSpdx =
    formatLabel?.toUpperCase() === 'SPDX' ||
    sbom.format?.toLowerCase() === 'spdx' ||
    sbom.original_format?.toLowerCase() === 'spdx';

  const conversionStatus = sbom.conversion_status;

  useEffect(() => {
    setConvertedId(sbom.converted_sbom_id ?? null);
    setEnrichmentStatus(sbom.enrichment_status ?? null);
  }, [sbom.converted_sbom_id, sbom.enrichment_status]);

  const reportQuery = useQuery({
    queryKey: ['sbom-conversion-report', sbom.id],
    queryFn: () => getSbomConversionReport(sbom.id),
    enabled: isSpdx && Boolean(conversionStatus || convertedId),
  });

  const enrichmentPollQuery = useQuery({
    queryKey: ['sbom-enrichment-status', sbom.id],
    queryFn: () => getSbom(sbom.id),
    enabled: isSpdx && (enrichmentStatus === 'pending' || enrichmentStatus === 'running'),
    refetchInterval: (query) => {
      const status = query.state.data?.enrichment_status;
      if (status === 'pending' || status === 'running') {
        return 3000;
      }
      return false;
    },
  });

  useEffect(() => {
    const polled = enrichmentPollQuery.data?.enrichment_status;
    if (polled && polled !== enrichmentStatus) {
      setEnrichmentStatus(polled);
      if (polled === 'completed') {
        setMessage('Lifecycle enrichment completed.');
      } else if (polled === 'failed') {
        setMessage(
          enrichmentPollQuery.data?.enrichment_error ||
            'Lifecycle enrichment failed. Use manual refresh on the converted SBOM.',
        );
      }
    }
  }, [enrichmentPollQuery.data, enrichmentStatus]);

  const convertMutation = useMutation({
    mutationFn: () => convertSbomToCycloneDX(sbom.id),
    onSuccess: (result) => {
      setConvertedId(result.converted_sbom_id);
      setEnrichmentStatus(result.enrichment_status || 'pending');
      invalidateSbomConversionSurfaces(qc, sbom.id, result.converted_sbom_id);
      setMessage(
        result.message ||
          'Converted to CycloneDX. Lifecycle enrichment is running in background.',
      );
      showSuccess('SBOM was converted to CycloneDX successfully.');
    },
    onError: (err: Error) => {
      if (isTimeoutError(err)) {
        setMessage(
          'Conversion timed out. The server may still be processing — refresh this page in a moment.',
        );
        return;
      }
      const safeMessage = getApiErrorMessage(err, 'SBOM conversion failed. Please try again.');
      setMessage(safeMessage);
      showError(safeMessage);
    },
  });

  if (!isSpdx) {
    return null;
  }

  const handleExport = async (label: string, loader: () => Promise<{ blob: Blob; filename: string }>) => {
    setMessage(`Preparing ${label}…`);
    try {
      const { blob, filename } = await loader();
      triggerDownload(blob, filename);
      setMessage(`Downloaded ${filename}.`);
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : `${label} download failed.`);
    }
  };

  const statusBadge = () => {
    if (convertMutation.isPending) {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-hcl-blue">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Converting…
        </span>
      );
    }
    if (conversionStatus === 'failed') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-600">
          <XCircle className="h-3.5 w-3.5" /> Conversion failed
        </span>
      );
    }
    if (conversionStatus === 'completed_with_warnings') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-600">
          <AlertTriangle className="h-3.5 w-3.5" /> Completed with warnings
        </span>
      );
    }
    if (conversionStatus === 'completed' || convertedId) {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-green-600">
          <CheckCircle2 className="h-3.5 w-3.5" /> Conversion completed
        </span>
      );
    }
    return <span className="text-xs text-hcl-muted">Not converted</span>;
  };

  const enrichmentBadge = () => {
    const status = enrichmentStatus || reportQuery.data?.enrichment_status;
    if (!status) return null;
    if (status === 'pending' || status === 'running') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-hcl-blue">
          <Loader2 className="h-3 w-3 animate-spin" />
          Enrichment {status === 'running' ? 'running' : 'pending'}
        </span>
      );
    }
    if (status === 'completed') {
      return <span className="text-xs font-medium text-green-600">Enrichment completed</span>;
    }
    if (status === 'failed') {
      return <span className="text-xs font-medium text-red-600">Enrichment failed</span>;
    }
    return null;
  };

  const report: SbomConversionReport | undefined = reportQuery.data;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4">
        <div>
          <CardTitle className="flex items-center gap-2">
            <ArrowRightLeft className="h-4 w-4" />
            SPDX to CycloneDX Conversion
          </CardTitle>
          <p className="mt-1 text-xs text-hcl-muted">
            Convert SPDX packages to CycloneDX for lifecycle enrichment and export.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          {statusBadge()}
          {enrichmentBadge()}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            onClick={() => convertMutation.mutate()}
            loading={convertMutation.isPending}
            disabled={convertMutation.isPending || Boolean(convertedId)}
          >
            Convert to CycloneDX
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              handleExport('Original SPDX', () =>
                exportSbomDocument(sbom.id, { format: 'spdx', exportMode: 'original' }),
              )
            }
          >
            <Download className="h-3.5 w-3.5" /> Export Original SPDX
          </Button>
          {convertedId && (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  handleExport('Converted CycloneDX', () =>
                    exportSbomDocument(sbom.id, { format: 'cyclonedx', exportMode: 'converted' }),
                  )
                }
              >
                <Download className="h-3.5 w-3.5" /> Export Converted CycloneDX
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  handleExport('Enriched CycloneDX', () =>
                    exportSbomDocument(sbom.id, { format: 'cyclonedx', exportMode: 'enriched' }),
                  )
                }
              >
                <Download className="h-3.5 w-3.5" /> Export Enriched CycloneDX
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  handleExport('Conversion Report', () =>
                    exportSbomDocument(sbom.id, { format: 'conversion-report' }),
                  )
                }
              >
                <FileJson className="h-3.5 w-3.5" /> View Conversion Report
              </Button>
            </>
          )}
        </div>

        {convertedId && (
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div>
              <dt className="text-xs font-medium text-hcl-muted uppercase">Converted SBOM</dt>
              <dd className="mt-1 font-medium text-hcl-navy">
                <Link href={`/sboms/${convertedId}`} className="text-hcl-blue hover:underline">
                  #{convertedId}
                </Link>
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted uppercase">Packages</dt>
              <dd className="mt-1 font-medium text-hcl-navy">{report?.package_count ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted uppercase">Dependencies mapped</dt>
              <dd className="mt-1 font-medium text-hcl-navy">{report?.mapped_relationships ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted uppercase">Warnings</dt>
              <dd className="mt-1 font-medium text-hcl-navy">{report?.warnings?.length ?? 0}</dd>
            </div>
          </dl>
        )}

        {showReport && report && report.warnings.length > 0 && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900 space-y-1 max-h-40 overflow-y-auto">
            {report.warnings.map((warning, index) => (
              <p key={index}>{warning}</p>
            ))}
          </div>
        )}

        {convertedId && report && report.warnings.length > 0 && !showReport && (
          <button
            type="button"
            className="text-xs text-hcl-blue hover:underline font-semibold"
            onClick={() => setShowReport(true)}
          >
            Show {report.warnings.length} conversion warning(s)
          </button>
        )}

        {message && (
          <p className={`text-xs ${isTimeoutError({ message } as Error) ? 'text-amber-700' : 'text-hcl-muted'}`}>
            {message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
