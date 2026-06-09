'use client';

import { useState, type FormEvent, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, Send, Sparkles } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { askCopilot, getCopilotBriefing, HttpError } from '@/lib/api';
import { cn } from '@/lib/utils';

/**
 * AI Security Copilot — grounded executive briefing + ask-anything.
 *
 * The briefing is generated server-side from the canonical metrics
 * snapshot (never from raw SBOM contents) and server-cached per data
 * state, so reopening the dashboard does not re-bill the LLM. Questions
 * are one-shot and grounded in the same snapshot — the model is
 * instructed to cite only numbers that exist.
 *
 * The panel hides itself entirely when the AI surface is disabled
 * (403/404 from the rollout gate) — same behaviour as the AI-fix UI.
 */

const SUGGESTED_QUESTIONS = [
  'What got worse this week?',
  'Which SBOM should we patch first?',
  'Are we meeting our SLAs?',
];

/** Minimal markdown: **bold**, bullet lines, paragraphs. No new deps. */
function renderMarkdownLite(md: string): ReactNode {
  const renderInline = (text: string, keyBase: string): ReactNode[] =>
    text.split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
      part.startsWith('**') && part.endsWith('**') ? (
        <strong key={`${keyBase}-${i}`} className="font-semibold text-hcl-navy">
          {part.slice(2, -2)}
        </strong>
      ) : (
        <span key={`${keyBase}-${i}`}>{part}</span>
      ),
    );

  const blocks: ReactNode[] = [];
  let bullets: string[] = [];
  const flushBullets = (key: string) => {
    if (!bullets.length) return;
    blocks.push(
      <ul key={key} className="ml-4 list-disc space-y-1">
        {bullets.map((b, i) => (
          <li key={i}>{renderInline(b, `${key}-${i}`)}</li>
        ))}
      </ul>,
    );
    bullets = [];
  };
  md.split('\n').forEach((raw, idx) => {
    const line = raw.trim();
    if (line.startsWith('- ') || line.startsWith('* ')) {
      bullets.push(line.slice(2));
      return;
    }
    flushBullets(`ul-${idx}`);
    if (line) blocks.push(<p key={`p-${idx}`}>{renderInline(line, `p-${idx}`)}</p>);
  });
  flushBullets('ul-end');
  return <div className="space-y-2">{blocks}</div>;
}

function copilotErrorCopy(err: unknown): string {
  if (err instanceof HttpError) {
    if (err.status === 429) return 'AI budget cap reached for today — the Copilot will be back when the cap resets.';
    if (err.status === 502) return 'The AI provider is unreachable right now. Check Settings → AI, then try again.';
  }
  return 'The Copilot hit an unexpected error. Try again in a moment.';
}

function isAiDisabled(err: unknown): boolean {
  return err instanceof HttpError && (err.status === 403 || err.status === 404);
}

export function CopilotPanel() {
  const queryClient = useQueryClient();
  const [question, setQuestion] = useState('');

  const briefingQuery = useQuery({
    queryKey: ['copilot-briefing'],
    queryFn: ({ signal }) => getCopilotBriefing(false, signal),
    staleTime: 5 * 60_000,
    retry: false,
  });

  // Regenerate replaces the cached briefing in place — setQueryData keeps
  // every dashboard consumer of ['copilot-briefing'] in sync.
  const regenerate = useMutation({
    mutationFn: () => getCopilotBriefing(true),
    onSuccess: (data) => {
      queryClient.setQueryData(['copilot-briefing'], data);
    },
  });

  // @no-invalidation-needed — read-only probe over the metrics snapshot;
  // asking a question mutates no server-side resource any list view shows.
  const ask = useMutation({
    mutationFn: (q: string) => askCopilot(q),
  });

  // AI surface disabled → no panel at all (AiConfigBanner owns the nudge).
  if (isAiDisabled(briefingQuery.error)) return null;

  const briefing = briefingQuery.data;
  const busy = briefingQuery.isLoading || regenerate.isPending;

  const submitQuestion = (e: FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (q && !ask.isPending) ask.mutate(q);
  };

  return (
    <Surface variant="elevated" className="relative overflow-hidden">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-hcl-blue via-hcl-cyan to-hcl-violet"
      />
      <SurfaceHeader>
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-hcl-blue to-hcl-violet text-white">
            <Sparkles className="h-4 w-4" aria-hidden />
          </span>
          <div>
            <h3 className="text-base font-semibold text-hcl-navy">AI Security Copilot</h3>
            <p className="mt-0.5 text-xs text-hcl-muted">
              Briefing grounded in your live metrics — numbers only, no invention
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => regenerate.mutate()}
          disabled={busy}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-2.5 py-1.5 text-xs font-medium text-hcl-navy',
            'transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
            'disabled:cursor-not-allowed disabled:opacity-60',
          )}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', regenerate.isPending && 'animate-spin')} aria-hidden />
          Refresh briefing
        </button>
      </SurfaceHeader>
      <SurfaceContent>
        {/* Briefing */}
        {busy ? (
          <div className="flex h-28 items-center justify-center gap-3 text-xs text-hcl-muted">
            <Spinner />
            {regenerate.isPending ? 'Regenerating briefing…' : 'Reading your portfolio…'}
          </div>
        ) : briefingQuery.isError || regenerate.isError ? (
          <div className="rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
            {copilotErrorCopy(regenerate.error ?? briefingQuery.error)}
          </div>
        ) : briefing ? (
          <>
            <div className="text-sm leading-relaxed text-hcl-navy/90 dark:text-hcl-navy">
              {renderMarkdownLite(briefing.briefing)}
            </div>
            <p className="mt-2 text-[10px] text-hcl-muted">
              {briefing.provider} · {briefing.model} ·{' '}
              {briefing.cached ? 'cached' : `$${briefing.cost_usd.toFixed(4)}`} · generated{' '}
              {briefing.generated_at.slice(0, 16).replace('T', ' ')} UTC
            </p>
          </>
        ) : null}

        {/* Ask */}
        <form onSubmit={submitQuestion} className="mt-4 border-t border-border-subtle pt-3">
          <label htmlFor="copilot-question" className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
            Ask about your portfolio
          </label>
          <div className="mt-1.5 flex gap-2">
            <input
              id="copilot-question"
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              maxLength={500}
              placeholder="e.g. Which SBOM should we patch first?"
              className={cn(
                'min-w-0 flex-1 rounded-lg border border-border-subtle bg-surface px-3 py-2 text-sm text-hcl-navy placeholder:text-hcl-muted/70',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
              )}
            />
            <button
              type="submit"
              disabled={ask.isPending || question.trim().length === 0}
              aria-label="Ask the Copilot"
              className={cn(
                'inline-flex items-center gap-1.5 rounded-lg bg-hcl-blue px-3 py-2 text-sm font-medium text-white',
                'transition-colors hover:bg-hcl-blue/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                'disabled:cursor-not-allowed disabled:opacity-60',
              )}
            >
              {ask.isPending ? <Spinner className="h-4 w-4" /> : <Send className="h-4 w-4" aria-hidden />}
              Ask
            </button>
          </div>
          {!ask.data && !ask.isPending && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {SUGGESTED_QUESTIONS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => {
                    setQuestion(q);
                    ask.mutate(q);
                  }}
                  className="rounded-full border border-border-subtle px-2.5 py-1 text-[11px] text-hcl-muted transition-colors hover:bg-surface-muted hover:text-hcl-navy"
                >
                  {q}
                </button>
              ))}
            </div>
          )}
          {ask.isError && (
            <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">{copilotErrorCopy(ask.error)}</p>
          )}
          {ask.data && (
            <div className="mt-3 rounded-lg bg-surface-muted/60 px-3 py-2.5">
              <p className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                {ask.data.question}
              </p>
              <div className="mt-1.5 text-sm leading-relaxed text-hcl-navy/90 dark:text-hcl-navy">
                {renderMarkdownLite(ask.data.answer)}
              </div>
            </div>
          )}
        </form>
      </SurfaceContent>
    </Surface>
  );
}
