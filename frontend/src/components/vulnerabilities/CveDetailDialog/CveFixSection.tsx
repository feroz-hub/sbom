'use client';

import { useMemo, useState, useCallback } from 'react';
import { Copy, Check, Wrench, ArrowUpRight } from 'lucide-react';
import { useToast } from '@/hooks/useToast';
import { cn } from '@/lib/utils';
import type {
  CveDetail,
  CveDetailWithContext,
  CveFixVersion,
} from './types';

interface CveFixSectionProps {
  detail: CveDetail | CveDetailWithContext;
}

function isContext(d: CveDetail | CveDetailWithContext): d is CveDetailWithContext {
  return 'current_version_status' in d;
}

const ECOSYSTEM_INSTALL: Record<string, (pkg: string, version: string) => string> = {
  npm: (p, v) => `npm install ${p}@${v}`,
  PyPI: (p, v) => `pip install ${p}==${v}`,
  pypi: (p, v) => `pip install ${p}==${v}`,
  Maven: (p, v) => `mvn -Dversion=${v} ${p}`,
  RubyGems: (p, v) => `gem install ${p} -v ${v}`,
  rubygems: (p, v) => `gem install ${p} -v ${v}`,
  NuGet: (p, v) => `dotnet add package ${p} --version ${v}`,
  nuget: (p, v) => `dotnet add package ${p} --version ${v}`,
  Go: (p, v) => `go get ${p}@${v}`,
  go: (p, v) => `go get ${p}@${v}`,
  cargo: (p, v) => `cargo update -p ${p} --precise ${v}`,
  Cargo: (p, v) => `cargo update -p ${p} --precise ${v}`,
};

function installCommand(ecosystem: string, pkg: string, version: string): string | null {
  const fn = ECOSYSTEM_INSTALL[ecosystem] ?? ECOSYSTEM_INSTALL[ecosystem.toLowerCase()];
  return fn ? fn(pkg, version) : null;
}

/**
 * Section 3 — "How do I fix it?"
 * Scan-aware: leads with the recommended-upgrade callout. Below: a grouped
 * fix-version table per ecosystem; copy-to-clipboard buttons for the
 * appropriate package-manager command.
 */
export function CveFixSection({ detail }: CveFixSectionProps) {
  const { showToast } = useToast();
  const [copied, setCopied] = useState<string | null>(null);

  const grouped = useMemo(() => {
    const m = new Map<string, CveFixVersion[]>();
    for (const fv of detail.fix_versions) {
      const key = fv.ecosystem || 'unknown';
      const list = m.get(key) ?? [];
      list.push(fv);
      m.set(key, list);
    }
    return Array.from(m.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [detail.fix_versions]);

  const ctx = isContext(detail) ? detail : null;
  const status = ctx?.current_version_status ?? 'unknown';
  const recommended = ctx?.recommended_upgrade ?? null;
  const componentName = ctx?.component?.name ?? null;
  const currentVersion = ctx?.component?.version ?? null;
  const ecosystem = ctx?.component?.ecosystem ?? null;

  const onCopy = useCallback(
    async (cmd: string) => {
      if (typeof navigator === 'undefined' || !navigator.clipboard) return;
      try {
        await navigator.clipboard.writeText(cmd);
        setCopied(cmd);
        showToast('Copied install command', 'success', { duration: 2000 });
        setTimeout(() => setCopied(null), 1500);
      } catch {
        showToast('Could not copy command', 'error');
      }
    },
    [showToast],
  );

  return (
    <section className="space-y-3 border-t border-border-subtle px-6 py-3" aria-labelledby="cve-fix-heading">
      <h3
        id="cve-fix-heading"
        className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
      >
        How do I fix it?
      </h3>

      {ctx && status === 'vulnerable' && recommended && componentName ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50/60 px-3 py-3 text-sm dark:border-emerald-900/60 dark:bg-emerald-950/30">
          <p className="text-emerald-900 dark:text-emerald-200">
            <ArrowUpRight className="inline h-4 w-4" aria-hidden />{' '}
            Upgrade <code className="font-mono font-semibold">{componentName}</code>
            {currentVersion ? (
              <>
                {' '}from <code className="font-mono">{currentVersion}</code>
              </>
            ) : null}
            {' '}to <code className="font-mono font-semibold">{recommended}</code>.
          </p>
          {ecosystem ? (
            (() => {
              const cmd = installCommand(ecosystem, componentName, recommended);
              if (!cmd) return null;
              const isCopied = copied === cmd;
              return (
                <button
                  type="button"
                  onClick={() => onCopy(cmd)}
                  className={cn(
                    'mt-2 inline-flex items-center gap-2 rounded border border-emerald-300 bg-white px-2 py-1',
                    'font-mono text-xs text-emerald-900 hover:bg-emerald-50',
                    'min-h-[36px]',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/40',
                  )}
                  aria-label={`Copy command: ${cmd}`}
                >
                  <span>{cmd}</span>
                  {isCopied ? <Check className="h-3 w-3" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
                </button>
              );
            })()
          ) : null}
        </div>
      ) : ctx && status === 'fixed' ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50/60 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200">
          The detected version is already at-or-above every published fix. No action required.
        </div>
      ) : null}

      {grouped.length === 0 ? (
        <p className="text-sm text-hcl-muted">
          No fix versions are available from any source yet.
        </p>
      ) : (
        <div className="space-y-3">
          {grouped.map(([eco, rows]) => (
            <div key={eco}>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                {eco}
              </p>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {rows.map((row, i) => (
                  <li
                    key={`${row.package}-${row.fixed_in ?? row.range ?? i}`}
                    className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 font-metric text-[11px] font-semibold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                  >
                    <Wrench className="h-2.5 w-2.5" aria-hidden />
                    {row.package}
                    {row.fixed_in ? (
                      <>
                        <span className="opacity-60">→</span>
                        <span>{row.fixed_in}</span>
                      </>
                    ) : row.range ? (
                      <span className="opacity-80 font-mono text-[10px]">{row.range}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {detail.workaround ? (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            Workaround
          </p>
          <p className="mt-1 text-sm leading-relaxed text-foreground/90 whitespace-pre-line">
            {detail.workaround}
          </p>
        </div>
      ) : null}
    </section>
  );
}
