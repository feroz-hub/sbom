'use client';

import { ExternalLink } from 'lucide-react';
import { formatDateShort } from '@/lib/utils';
import type { CveDetail, CveRowSeed } from './types';

interface CveWhatSectionProps {
  seed: CveRowSeed;
  detail: CveDetail;
  scanName?: string | null;
  /** Stable id surfaced for aria-describedby on the parent dialog. */
  describedById?: string;
}

/**
 * Section 1 — "What is this CVE?"
 * Title + summary prose + component context + dates + CWE chips.
 * Summary is rendered as plain text (Pydantic max_length=2000 is the
 * enforcement boundary). No HTML escapes the backend.
 */
export function CveWhatSection({ seed, detail, scanName, describedById }: CveWhatSectionProps) {
  const componentLine =
    seed.component_name && seed.component_version
      ? `Detected in ${seed.component_name}@${seed.component_version}`
      : seed.component_name
        ? `Detected in ${seed.component_name}`
        : null;

  return (
    <section className="space-y-3 px-6 py-3" aria-labelledby="cve-what-heading">
      <h3
        id="cve-what-heading"
        className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
      >
        What is this CVE?
      </h3>

      <p
        id={describedById}
        className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line"
      >
        {detail.summary || 'No description available from any source.'}
      </p>

      {componentLine ? (
        <p className="text-xs text-hcl-muted">
          {componentLine}
          {scanName ? <span> · via {scanName}</span> : null}
        </p>
      ) : null}

      <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
        {detail.published_at ? (
          <div>
            <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              Published
            </span>
            <span className="font-metric tabular-nums text-foreground/80" title={detail.published_at}>
              {formatDateShort(detail.published_at)}
            </span>
          </div>
        ) : null}
        {detail.modified_at ? (
          <div>
            <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              Last modified
            </span>
            <span className="font-metric tabular-nums text-foreground/80" title={detail.modified_at}>
              {formatDateShort(detail.modified_at)}
            </span>
          </div>
        ) : null}
        {detail.aliases.length > 0 ? (
          <div className="min-w-0">
            <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              Aliases
            </span>
            <span className="font-mono text-[11px] text-foreground/80">
              {detail.aliases.slice(0, 4).join(', ')}
              {detail.aliases.length > 4 ? ` +${detail.aliases.length - 4}` : ''}
            </span>
          </div>
        ) : null}
      </div>

      {detail.cwe_ids.length > 0 ? (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            Weakness types (CWE)
          </p>
          <div className="mt-1 flex flex-wrap gap-1">
            {detail.cwe_ids.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
              >
                {cwe}
                <ExternalLink className="h-2.5 w-2.5" aria-hidden />
              </a>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
