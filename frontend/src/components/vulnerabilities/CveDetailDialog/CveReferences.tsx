'use client';

import { ExternalLink } from 'lucide-react';
import { formatDateShort } from '@/lib/utils';
import type { CveDetail, CveSourceName } from './types';

const SOURCE_LABEL: Record<CveSourceName, string> = {
  osv: 'OSV',
  ghsa: 'GHSA',
  nvd: 'NVD',
  epss: 'EPSS',
  kev: 'CISA KEV',
};

const UPSTREAM_LINKS: Array<{
  source: CveSourceName;
  label: string;
  build: (cve: string) => string;
}> = [
  { source: 'ghsa', label: 'Open in GHSA', build: (id) => `https://github.com/advisories/${id}` },
  { source: 'nvd', label: 'Open in NVD', build: (id) => `https://nvd.nist.gov/vuln/detail/${id}` },
  { source: 'osv', label: 'Open in OSV', build: (id) => `https://osv.dev/vulnerability/${id}` },
];

/**
 * Footer — opt-in upstream links + sources used + last fetched.
 */
export function CveReferences({ detail }: { detail: CveDetail }) {
  // Pick the best alias for each upstream link target.
  const ghsaAlias = detail.aliases.find((a) => a.startsWith('GHSA-'));

  return (
    // Border + bg are provided by the Dialog footer wrapper; this element
    // owns only its inner spacing + content.
    <footer
      className="space-y-2 px-6 py-3 text-xs text-hcl-muted"
      aria-labelledby="cve-references-heading"
    >
      <h3 id="cve-references-heading" className="sr-only">
        References
      </h3>

      <div className="flex flex-wrap items-center gap-2">
        {UPSTREAM_LINKS.map(({ source, label, build }) => {
          const target = source === 'ghsa' && ghsaAlias ? ghsaAlias : detail.cve_id;
          return (
            <a
              key={source}
              href={build(target)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-2 py-1 min-h-[36px] text-[11px] font-medium text-hcl-blue hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
            >
              {label}
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          );
        })}
      </div>

      {detail.references.length > 0 ? (
        <details className="group">
          <summary className="cursor-pointer text-[11px] font-medium text-hcl-blue hover:underline">
            All references ({detail.references.length})
          </summary>
          <ul className="mt-2 space-y-1">
            {detail.references.map((r) => (
              <li key={r.url} className="truncate">
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                  title={r.url}
                >
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                    {r.type}
                  </span>
                  <span className="font-mono text-[11px]">{r.url}</span>
                  <ExternalLink className="h-2.5 w-2.5" aria-hidden />
                </a>
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <span>
          <span className="font-semibold">Sources used:</span>{' '}
          {detail.sources_used.length > 0
            ? detail.sources_used.map((s) => SOURCE_LABEL[s]).join(' · ')
            : 'none'}
        </span>
        <span title={detail.fetched_at}>
          Last fetched: {formatDateShort(detail.fetched_at)}
        </span>
        {detail.is_partial ? (
          <span className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-amber-800 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-200">
            partial data
          </span>
        ) : null}
      </div>
    </footer>
  );
}
