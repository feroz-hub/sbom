'use client';

import { ArrowRight, Check } from 'lucide-react';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import type { CompareResult } from '@/types/compare';

interface Props {
  result: CompareResult;
  onViewSharedFindings: () => void;
}

/**
 * Region 2 replacement for the identical-runs case.
 *
 * Triggered when added + resolved + severity_changed === 0 (regardless of
 * unchanged count). Three sub-states:
 *
 *   1. Both runs have findings, all matched → "No changes detected.
 *      Both runs share N findings…"
 *   2. Both runs entirely empty → "No vulnerabilities in either run…"
 *   3. Cross-SBOM with zero overlap → "Different SBOMs, no overlapping
 *      vulnerabilities."
 *
 * The CTA jumps to the Findings tab with show_unchanged=true so the user
 * can browse the shared set even though it's not a "diff."
 */
export function IdenticalRunsCard({ result, onViewSharedFindings }: Props) {
  const unchanged = result.posture.findings_unchanged_count;
  const a_total = result.run_a.total_findings;
  const b_total = result.run_b.total_findings;
  const sameSbom = result.relationship.same_sbom;
  const sub = subLineFor(result);

  const variant = (() => {
    if (unchanged === 0 && a_total === 0 && b_total === 0) {
      return 'both-clean' as const;
    }
    if (unchanged === 0) {
      return 'no-overlap' as const;
    }
    return 'shared' as const;
  })();

  return (
    <Surface variant="gradient" elevation={2}>
      <SurfaceContent className="space-y-4 py-8 text-center sm:py-10">
        <div
          aria-hidden
          className="mx-auto inline-flex h-14 w-14 items-center justify-center rounded-full bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-300"
        >
          <Check className="h-7 w-7" strokeWidth={3} />
        </div>

        <h2
          className="font-semibold text-hcl-navy"
          style={{
            fontSize: 'var(--hero-headline-size)',
            letterSpacing: 'var(--hero-headline-tracking)',
            lineHeight: 1.15,
          }}
        >
          {variant === 'both-clean' && 'No vulnerabilities in either run.'}
          {variant === 'no-overlap' && 'No overlapping vulnerabilities.'}
          {variant === 'shared' && 'No changes detected.'}
        </h2>

        <p className="mx-auto max-w-2xl text-sm text-hcl-muted">
          {variant === 'both-clean' && (
            <>
              Both <strong className="text-hcl-navy">Run #{result.run_a.id}</strong> and{' '}
              <strong className="text-hcl-navy">Run #{result.run_b.id}</strong> produced
              clean scans.
            </>
          )}
          {variant === 'no-overlap' && (
            <>
              Run A and Run B do not share any findings. This is expected for
              a cross-SBOM compare with disjoint dependency trees.
            </>
          )}
          {variant === 'shared' && (
            <>
              Both runs share{' '}
              <strong className="text-hcl-navy">{unchanged.toLocaleString()}</strong>{' '}
              finding{unchanged === 1 ? '' : 's'}; none added, resolved, or
              reclassified.
            </>
          )}
        </p>

        {sub && (
          <p className="mx-auto max-w-2xl text-sm italic text-hcl-muted">
            {sameSbom ? `Same SBOM ${sub} — confirms vulnerability feed was stable in this window.` : sub}
          </p>
        )}

        {variant === 'shared' && unchanged > 0 && (
          <div className="pt-2">
            <button
              type="button"
              onClick={onViewSharedFindings}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium text-hcl-navy transition-colors hover:bg-hcl-light/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
            >
              View shared findings ({unchanged.toLocaleString()})
              <ArrowRight className="h-4 w-4" aria-hidden />
            </button>
          </div>
        )}
      </SurfaceContent>
    </Surface>
  );
}

function subLineFor(result: CompareResult): string | null {
  const days = result.relationship.days_between;
  if (days == null) return null;
  if (days < 1 / 24) return 're-scanned <1h apart';
  if (days < 1) return `re-scanned ${Math.round(days * 24)}h apart`;
  return `re-scanned ${days.toFixed(days < 10 ? 1 : 0)} days apart`;
}

export function isIdenticalRuns(result: CompareResult): boolean {
  const p = result.posture;
  return (
    p.findings_added_count === 0 &&
    p.findings_resolved_count === 0 &&
    p.findings_severity_changed_count === 0
  );
}
