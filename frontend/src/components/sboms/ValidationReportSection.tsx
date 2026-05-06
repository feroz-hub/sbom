'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Copy, Check, Download, AlertOctagon, AlertTriangle, Info, Upload, ExternalLink, BookOpen } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import {
  groupEntriesByStage,
  severityChipClasses,
  stageLabel,
  stageNumber,
  validationStatusMeta,
} from '@/lib/sbomValidation';
import { validationCodeAnchor } from '@/lib/validationCodeReference';
import type { ValidationErrorEntry, ValidationReport } from '@/types';

interface ValidationReportSectionProps {
  report: ValidationReport;
  /** Click handler for the "Re-upload" affordance — opens the upload modal. */
  onReupload?: () => void;
}

const SEVERITY_ICON: Record<string, typeof AlertOctagon> = {
  error: AlertOctagon,
  warning: AlertTriangle,
  info: Info,
};

function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function EntryCard({ entry }: { entry: ValidationErrorEntry }) {
  const [copied, setCopied] = useState(false);
  const Icon = SEVERITY_ICON[entry.severity] ?? Info;
  const stageNum = entry.stage_number ?? stageNumber(entry.stage);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(entry, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <article
      className="rounded-lg border border-hcl-border bg-surface p-4 shadow-sm"
      aria-labelledby={`entry-${entry.code}-${entry.path}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <Icon
            className={
              entry.severity === 'error'
                ? 'h-4 w-4 mt-0.5 shrink-0 text-red-600 dark:text-red-400'
                : entry.severity === 'warning'
                ? 'h-4 w-4 mt-0.5 shrink-0 text-amber-600 dark:text-amber-400'
                : 'h-4 w-4 mt-0.5 shrink-0 text-slate-500 dark:text-slate-400'
            }
            aria-hidden
          />
          <div className="min-w-0">
            <h4
              id={`entry-${entry.code}-${entry.path}`}
              className="font-mono text-xs font-semibold break-all"
            >
              <Link
                href={validationCodeAnchor(entry.code)}
                className="inline-flex items-center gap-1 text-hcl-navy hover:text-hcl-blue hover:underline"
                aria-label={`View reference for ${entry.code}`}
              >
                {entry.code}
                <BookOpen className="h-3 w-3 shrink-0 text-hcl-muted" aria-hidden />
              </Link>
            </h4>
            <p className="text-xs text-hcl-muted">
              Stage {stageNum} · {stageLabel(entry.stage)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${severityChipClasses(
              entry.severity,
            )}`}
          >
            {entry.severity}
          </span>
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1 rounded-md border border-hcl-border px-2 py-1 text-xs text-hcl-muted hover:text-hcl-navy hover:bg-hcl-light transition-colors"
            aria-label={`Copy ${entry.code} as JSON`}
          >
            {copied ? <Check className="h-3 w-3" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </header>

      {entry.path && (
        <dl className="mt-3 grid gap-1 text-sm">
          <dt className="text-xs font-medium uppercase tracking-wide text-hcl-muted">Path</dt>
          <dd className="font-mono text-xs text-hcl-navy break-all">{entry.path}</dd>
        </dl>
      )}

      <p className="mt-3 text-sm text-hcl-navy break-words">{entry.message}</p>

      {entry.remediation && (
        <p className="mt-2 text-sm text-hcl-muted">
          <span className="font-medium text-hcl-navy">Remediation: </span>
          {entry.remediation}
        </p>
      )}

      {entry.spec_reference && (
        <p className="mt-2 text-xs">
          <a
            href={`https://www.google.com/search?q=${encodeURIComponent(entry.spec_reference)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-hcl-blue hover:underline"
          >
            {entry.spec_reference}
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        </p>
      )}
    </article>
  );
}

export function ValidationReportSection({ report, onReupload }: ValidationReportSectionProps) {
  const meta = validationStatusMeta(report.status, report.warning_count);
  const grouped = useMemo(() => groupEntriesByStage(report.entries), [report.entries]);
  const isFailed = report.status === 'failed' || report.status === 'quarantined';
  const isClean = report.status === 'validated' && report.warning_count === 0;

  const headlineCounts: string[] = [];
  if (report.error_count > 0) headlineCounts.push(`${report.error_count} error${report.error_count === 1 ? '' : 's'}`);
  if (report.warning_count > 0) headlineCounts.push(`${report.warning_count} warning${report.warning_count === 1 ? '' : 's'}`);
  if (report.info_count > 0) headlineCounts.push(`${report.info_count} info`);

  const handleDownload = () => {
    const safe = report.filename.replace(/[^A-Za-z0-9._-]+/g, '_') || `sbom-${report.sbom_id}`;
    downloadJson(`${safe}.validation-report.json`, report);
  };

  return (
    <Card>
      <CardHeader className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <CardTitle>
            <span id={`validation-report-${report.sbom_id}`}>Validation report</span>
            <span
              className={`ml-3 inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${meta.classes}`}
            >
              {meta.label}
            </span>
          </CardTitle>
          <p className="mt-1 text-xs text-hcl-muted">
            {meta.description}
            {isFailed && report.failed_stage && (
              <>
                {' '}· Stopped at: <span className="font-medium text-hcl-navy">Stage {stageNumber(report.failed_stage)} — {stageLabel(report.failed_stage)}</span>
              </>
            )}
            {report.spec_detected && (
              <>
                {' '}· Format: <span className="font-medium text-hcl-navy">
                  {report.spec_detected.toUpperCase()}
                  {report.spec_version_detected ? ` ${report.spec_version_detected}` : ''}
                </span>
              </>
            )}
            {headlineCounts.length > 0 && <> · {headlineCounts.join(' · ')}</>}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {report.entries.length > 0 && (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={handleDownload}
              aria-label="Download validation report as JSON"
            >
              <Download className="h-4 w-4" aria-hidden />
              Download report (JSON)
            </Button>
          )}
          {isFailed && onReupload && (
            <Button type="button" size="sm" onClick={onReupload}>
              <Upload className="h-4 w-4" aria-hidden />
              Re-upload
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent>
        {isClean ? (
          <p className="text-sm text-hcl-muted">
            No issues found. This SBOM passed all 8 validation stages cleanly.
          </p>
        ) : report.entries.length === 0 ? (
          <p className="text-sm text-hcl-muted">No entries recorded.</p>
        ) : (
          <div className="space-y-6">
            {grouped.map(({ stage, entries }) => (
              <section key={stage} aria-labelledby={`stage-${stage}`}>
                <h3
                  id={`stage-${stage}`}
                  className="text-xs font-semibold uppercase tracking-wide text-hcl-muted mb-2"
                >
                  Stage {stageNumber(stage)} · {stageLabel(stage)}{' '}
                  <span className="font-normal text-hcl-muted">({entries.length})</span>
                </h3>
                <div className="space-y-3">
                  {entries.map((e, idx) => (
                    <EntryCard key={`${e.code}-${e.path}-${idx}`} entry={e} />
                  ))}
                </div>
              </section>
            ))}
            {report.truncated && (
              <p className="text-xs italic text-hcl-muted">
                Report was truncated server-side at 100 entries. Re-upload after fixing the listed issues to see any further problems.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
