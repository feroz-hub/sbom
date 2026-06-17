'use client';

import Link from 'next/link';
import { AlertTriangle, ArrowRightLeft, CheckCircle2, Download, FileJson, Loader2, XCircle } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import {
  convertSbomToCycloneDX,
  exportSbomDocument,
  getSbomConversionReport,
} from '@/lib/api';
import { invalidateSbomLists, invalidateSbomSurfaces } from '@/lib/queryInvalidation';
import type { SBOMSource, SbomConversionReport } from '@/types';

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

interface SbomConversionCardProps {
  sbom: SBOMSource;
  formatLabel?: string;
}

export function SbomConversionCard({ sbom, formatLabel }: SbomConversionCardProps) {
  const qc = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);
  const [showReport, setShowReport] = useState(false);

  const isSpdx =
    formatLabel?.toUpperCase() === 'SPDX' ||
    sbom.format?.toLowerCase() === 'spdx' ||
    sbom.original_format?.toLowerCase() === 'spdx';

  const conversionStatus = sbom.conversion_status;
  const convertedId = sbom.converted_sbom_id;

  const reportQuery = useQuery({
    queryKey: ['sbom-conversion-report', sbom.id],
    queryFn: () => getSbomConversionReport(sbom.id),
    enabled: isSpdx && Boolean(conversionStatus),
  });

  const convertMutation = useMutation({
    mutationFn: () => convertSbomToCycloneDX(sbom.id),
    onSuccess: (result) => {
      invalidateSbomSurfaces(qc, sbom.id);
      invalidateSbomLists(qc);
      if (result.converted_sbom_id) {
        invalidateSbomSurfaces(qc, result.converted_sbom_id);
      }
      qc.invalidateQueries({ queryKey: ['sbom-conversion-report', sbom.id] });
      setMessage(
        result.warnings.length > 0
          ? `Conversion completed with ${result.warnings.length} warning(s).`
          : 'Conversion completed successfully.',
      );
    },
    onError: (err: Error) => {
      setMessage(err.message || 'Conversion failed.');
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
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Conversion running
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
    if (conversionStatus === 'completed') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-green-600">
          <CheckCircle2 className="h-3.5 w-3.5" /> Conversion completed
        </span>
      );
    }
    return <span className="text-xs text-hcl-muted">Not converted</span>;
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
        {statusBadge()}
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

        {message && <p className="text-xs text-hcl-muted">{message}</p>}
      </CardContent>
    </Card>
  );
}
