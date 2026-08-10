'use client';

import { useState } from 'react';
import { Check, Copy, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import type { AiUpgradeCommand } from '@/types/ai';

interface UpgradeCommandCardProps {
  command: AiUpgradeCommand;
}

function riskCopy(risk: AiUpgradeCommand['breaking_change_risk']): {
  label: string;
  className: string;
  Icon: typeof ShieldCheck;
} {
  switch (risk) {
    case 'none':
      return { label: 'No expected breaking changes', className: 'text-emerald-700', Icon: ShieldCheck };
    case 'minor':
      return { label: 'Minor breaking-change risk', className: 'text-amber-700', Icon: ShieldAlert };
    case 'major':
      return { label: 'Major breaking-change risk', className: 'text-red-700', Icon: ShieldAlert };
    case 'unknown':
    default:
      return { label: 'Breaking-change risk unknown', className: 'text-hcl-muted', Icon: ShieldQuestion };
  }
}

export function UpgradeCommandCard({ command }: UpgradeCommandCardProps) {
  const [copied, setCopied] = useState(false);
  const risk = riskCopy(command.breaking_change_risk);

  const handleCopy = async () => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(command.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2_000);
    } catch {
      // Clipboard denied — leave the button alone, the text is still selectable.
    }
  };

  return (
    <section
      className="rounded-lg border border-border-subtle bg-surface-muted p-4"
      aria-labelledby="ai-upgrade-heading"
    >
      <div className="mb-2 flex items-center justify-between">
        <h4
          id="ai-upgrade-heading"
          className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
        >
          Recommended fix · {command.ecosystem}
        </h4>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs font-medium text-hcl-navy hover:bg-surface-muted"
          aria-label="Copy upgrade command"
        >
          {copied ? <Check className="h-3.5 w-3.5" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <p className="mb-3 text-sm font-medium text-hcl-navy">
        Upgrade to {command.target_version === 'n/a' ? 'a maintained replacement' : command.target_version}
      </p>

      <pre className="mb-3 overflow-x-auto rounded-md border border-border-subtle bg-surface px-3 py-2 text-[12px] leading-relaxed text-hcl-navy">
        <code>{command.command}</code>
      </pre>

      <p className="text-sm text-hcl-muted">{command.rationale}</p>

      <div className="mt-3 flex flex-col gap-1 text-xs">
        <span className={`inline-flex items-center gap-1 ${risk.className}`}>
          <risk.Icon className="h-3.5 w-3.5" aria-hidden />
          {risk.label}
        </span>
        <span className="text-hcl-muted">
          {command.tested_against_data ? (
            <>Verified against upstream fix-version data ✓</>
          ) : (
            <>
              <span className="font-medium">⚠ Inferred recommendation.</span> No upstream fix-version
              data was available — review before applying.
            </>
          )}
        </span>
      </div>
    </section>
  );
}
