import Link from 'next/link';
import type { Metadata } from 'next';
import { ArrowLeft, ExternalLink } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { stageLabel } from '@/lib/sbomValidation';
import {
  VALIDATION_CODE_REFERENCE,
  type ValidationCodeRef,
} from '@/lib/validationCodeReference';

export const metadata: Metadata = {
  title: 'SBOM validation error codes',
  description:
    'Reference for the codes emitted by the 8-stage SBOM validation pipeline — what each code means, common causes, and how to fix it.',
};

const SEVERITY_BADGE: Record<string, string> = {
  error: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800',
  warning:
    'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800',
  info: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800/60 dark:text-slate-300 dark:border-slate-700',
};

function CodeSection({ entry }: { entry: ValidationCodeRef }) {
  return (
    <section
      id={entry.anchor}
      className="scroll-mt-20 rounded-lg border border-hcl-border bg-surface p-5 shadow-sm"
      aria-labelledby={`${entry.anchor}-title`}
    >
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2
            id={`${entry.anchor}-title`}
            className="font-mono text-sm font-semibold text-hcl-navy break-all"
          >
            {entry.code}
          </h2>
          <p className="mt-1 text-xs text-hcl-muted">
            Stage {entry.stage_number} · {stageLabel(entry.stage)} · HTTP {entry.http_status}
          </p>
        </div>
        <span
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${
            SEVERITY_BADGE[entry.default_severity]
          }`}
        >
          {entry.default_severity}
        </span>
      </header>

      <p className="mt-4 text-sm text-hcl-navy">{entry.summary}</p>

      {entry.common_causes.length > 0 && (
        <div className="mt-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">
            Common causes
          </h3>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-hcl-navy">
            {entry.common_causes.map((cause, i) => (
              <li key={i}>{cause}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-4">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">How to fix</h3>
        <p className="mt-1 text-sm text-hcl-navy">{entry.how_to_fix}</p>
      </div>

      {entry.spec_link && (
        <p className="mt-4 text-xs">
          <a
            href={entry.spec_link.href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-hcl-blue hover:underline"
          >
            {entry.spec_link.label}
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        </p>
      )}
    </section>
  );
}

export default function SbomValidationErrorsPage() {
  // Group by stage so the Table of Contents is grouped instead of a long flat list.
  const byStage = new Map<number, { stage: string; entries: ValidationCodeRef[] }>();
  for (const entry of VALIDATION_CODE_REFERENCE) {
    const bucket = byStage.get(entry.stage_number);
    if (bucket) {
      bucket.entries.push(entry);
    } else {
      byStage.set(entry.stage_number, { stage: entry.stage, entries: [entry] });
    }
  }
  const groups = Array.from(byStage.entries())
    .sort(([a], [b]) => a - b)
    .map(([stage_number, { stage, entries }]) => ({ stage_number, stage, entries }));

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="SBOM validation error codes" />
      <div className="mx-auto w-full max-w-4xl space-y-6 px-6 py-6">
        <Link
          href="/sboms"
          className="inline-flex items-center gap-2 text-sm text-hcl-muted hover:text-hcl-navy transition-colors"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden /> Back to SBOMs
        </Link>

        <Card>
          <CardHeader>
            <CardTitle>About this reference</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-hcl-navy">
            <p>
              The SBOM validator runs an 8-stage pipeline against every uploaded document.
              Each stage may emit one or more codes describing what failed and how to fix it.
              The chip on a validation report links here so you can read the full description
              of any code without leaving the app.
            </p>
            <p className="text-hcl-muted">
              This page covers the codes most operators encounter in practice. The complete
              long-form reference, including the codes not surfaced here, lives at{' '}
              <code className="font-mono">docs/validation-error-codes.md</code> in the repository.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick navigation</CardTitle>
          </CardHeader>
          <CardContent>
            <nav aria-label="Table of contents">
              <ul className="grid gap-3 sm:grid-cols-2">
                {groups.map(({ stage_number, stage, entries }) => (
                  <li key={stage}>
                    <p className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">
                      Stage {stage_number} · {stageLabel(stage)}
                    </p>
                    <ul className="mt-1 space-y-1">
                      {entries.map((entry) => (
                        <li key={entry.code}>
                          <a
                            href={`#${entry.anchor}`}
                            className="font-mono text-xs text-hcl-blue hover:underline break-all"
                          >
                            {entry.code}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            </nav>
          </CardContent>
        </Card>

        {groups.map(({ stage_number, stage, entries }) => (
          <section key={stage} aria-labelledby={`stage-heading-${stage}`}>
            <h2
              id={`stage-heading-${stage}`}
              className="mb-3 text-base font-semibold text-hcl-navy"
            >
              Stage {stage_number} · {stageLabel(stage)}
            </h2>
            <div className="space-y-4">
              {entries.map((entry) => (
                <CodeSection key={entry.code} entry={entry} />
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
