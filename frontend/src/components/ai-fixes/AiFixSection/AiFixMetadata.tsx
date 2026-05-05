'use client';

import { Sparkles } from 'lucide-react';
import type { AiFixMetadata as AiFixMetadataType } from '@/types/ai';

interface AiFixMetadataProps {
  metadata: AiFixMetadataType;
  /** Re-issue the LLM call. */
  onRegenerate?: () => void;
  /** True while the regenerate mutation is in flight. */
  regenerating?: boolean;
}

function formatAge(seconds: number): string {
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

function formatCost(usd: number): string {
  if (usd === 0) return '$0.00';
  if (usd < 0.001) return '<$0.001';
  return `$${usd.toFixed(4)}`;
}

/**
 * Provenance row — the prompt's §4.3 hard rule: every AI-generated
 * artifact shows which provider produced it, when, and at what cost.
 */
export function AiFixMetadata({ metadata, onRegenerate, regenerating }: AiFixMetadataProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-hcl-muted">
      <div className="flex items-center gap-2">
        <Sparkles className="h-3.5 w-3.5 text-primary" aria-hidden />
        <span>
          {metadata.cache_hit ? 'Cached' : 'Generated'} {formatAge(metadata.age_seconds)}{' '}
          · {metadata.provider_used} <span className="text-hcl-muted/70">({metadata.model_used})</span>{' '}
          · {formatCost(metadata.total_cost_usd)}
        </span>
      </div>
      {onRegenerate ? (
        <button
          type="button"
          onClick={onRegenerate}
          disabled={regenerating}
          className="rounded-md border border-border-subtle bg-surface px-2 py-1 text-[11px] font-medium text-hcl-navy hover:bg-surface-muted disabled:cursor-progress disabled:opacity-60"
        >
          {regenerating ? 'Regenerating…' : 'Regenerate'}
        </button>
      ) : null}
    </div>
  );
}
