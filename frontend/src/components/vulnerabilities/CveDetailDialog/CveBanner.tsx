'use client';

import { AlertCircle, AlertTriangle, FileQuestion, Info, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import type { DialogState } from './states';

interface CveBannerProps {
  state: DialogState;
  onRetry?: () => void;
  /** GitHub issues / mailto link for the "report this" action on unrecognized + fatal. */
  reportIssueHref?: string;
}

/**
 * Renders the appropriate banner for the dialog's :type:`DialogState`.
 *
 * - ``loading`` and ``ok`` render no banner.
 * - ``partial`` / ``unreachable`` use amber.
 * - ``not_found`` / ``unrecognized`` use slate.
 * - ``fatal`` uses red.
 *
 * Retry is only on ``unreachable`` and ``fatal``; "Report" is only on
 * ``unrecognized`` and ``fatal``. Severity is conveyed by both colour
 * AND text (WCAG 2.2 — never colour-only).
 */
export function CveBanner({ state, onRetry, reportIssueHref }: CveBannerProps) {
  if (state.kind === 'loading' || state.kind === 'ok') return null;

  switch (state.kind) {
    case 'partial':
      return (
        <Banner tone="amber" Icon={AlertTriangle} headline="Some sources were unavailable">
          <p>This view may be incomplete.</p>
        </Banner>
      );

    case 'not_found':
      return (
        <Banner tone="slate" Icon={Info} headline="No advisory record found upstream">
          <p>
            We have what your scan reported, but no enriched details exist for this ID yet.
          </p>
        </Banner>
      );

    case 'unreachable':
      return (
        <Banner tone="amber" Icon={AlertCircle} headline="Couldn't reach the CVE database">
          <p>Showing what your scan already knew.</p>
          {onRetry ? (
            <div className="mt-2">
              <Button variant="secondary" onClick={onRetry} aria-label="Retry CVE enrichment">
                <RefreshCw className="h-4 w-4" aria-hidden />
                Retry
              </Button>
            </div>
          ) : null}
        </Banner>
      );

    case 'unrecognized':
      return (
        <Banner tone="slate" Icon={FileQuestion} headline="We don't recognize this advisory format">
          <p>
            Supported formats:{' '}
            <span className="font-mono text-[11px]">
              {state.supported.join(', ')}
            </span>
            .
          </p>
          {reportIssueHref ? (
            <p className="mt-2">
              <a
                href={reportIssueHref}
                target="_blank"
                rel="noopener noreferrer"
                className="text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
              >
                Report this issue ↗
              </a>
            </p>
          ) : null}
        </Banner>
      );

    case 'fatal':
      return (
        <Banner tone="red" Icon={AlertCircle} headline="Something went wrong">
          <p>We&apos;ve logged this. Please try again or report the issue.</p>
          <p className="mt-1 text-xs opacity-80">{state.message}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {onRetry ? (
              <Button variant="secondary" onClick={onRetry} aria-label="Retry">
                <RefreshCw className="h-4 w-4" aria-hidden />
                Retry
              </Button>
            ) : null}
            {reportIssueHref ? (
              <a
                href={reportIssueHref}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-2 py-1 min-h-[36px] text-[11px] font-medium text-hcl-blue hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
              >
                Report ↗
              </a>
            ) : null}
          </div>
        </Banner>
      );

    default: {
      const _exhaustive: never = state;
      void _exhaustive;
      return null;
    }
  }
}

interface BannerShellProps {
  tone: 'amber' | 'slate' | 'red';
  Icon: typeof AlertCircle;
  headline: string;
  children: React.ReactNode;
}

const TONE_CLASS: Record<BannerShellProps['tone'], string> = {
  amber:
    'border-amber-200 bg-amber-50/60 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200',
  slate:
    'border-slate-200 bg-slate-50/80 text-slate-900 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-200',
  red: 'border-red-200 bg-red-50/60 text-red-900 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200',
};

function Banner({ tone, Icon, headline, children }: BannerShellProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        'flex items-start gap-2 rounded-md border px-3 py-2 text-sm',
        TONE_CLASS[tone],
      )}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div className="space-y-1">
        <p className="font-semibold">{headline}</p>
        {children}
      </div>
    </div>
  );
}
