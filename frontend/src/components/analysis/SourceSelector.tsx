'use client';

import { Check, Database, Github, KeyRound, Layers, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { AnalysisConfig } from '@/lib/api';

export type SourceKey = 'NVD' | 'OSV' | 'GITHUB' | 'VULNDB';

interface SourceMeta {
  key: SourceKey;
  label: string;
  hint: string;
  Icon: typeof Database;
  /**
   * For GHSA/VulDB the source needs a server-side credential. NVD and OSV
   * work without credentials but NVD benefits from an API key (higher rate).
   */
  requiresCredential: boolean;
}

const SOURCES: SourceMeta[] = [
  {
    key: 'NVD',
    label: 'NVD',
    hint: 'NIST National Vulnerability Database — CPE-based matching',
    Icon: ShieldAlert,
    requiresCredential: false,
  },
  {
    key: 'OSV',
    label: 'OSV',
    hint: 'Google Open Source Vulnerabilities — PURL/ecosystem matching',
    Icon: Database,
    requiresCredential: false,
  },
  {
    key: 'GITHUB',
    label: 'GHSA',
    hint: 'GitHub Security Advisories — needs GITHUB_TOKEN env var',
    Icon: Github,
    requiresCredential: true,
  },
  {
    key: 'VULNDB',
    label: 'VulDB',
    hint: 'VulDB — needs VULNDB_API_KEY env var',
    Icon: KeyRound,
    requiresCredential: true,
  },
];

interface SourceSelectorProps {
  selected: SourceKey[];
  onChange: (next: SourceKey[]) => void;
  config: AnalysisConfig | undefined;
  /** Forces all toggles into a read-only state (e.g. while a run is in flight). */
  disabled?: boolean;
}

function isCredentialed(key: SourceKey, config: AnalysisConfig | undefined): boolean {
  if (!config) return true; // optimistic when config not yet loaded
  if (key === 'GITHUB') return !!config.github_configured;
  if (key === 'VULNDB') return !!config.vulndb_configured;
  // NVD works without an API key; OSV is keyless.
  return true;
}

export function SourceSelector({ selected, onChange, config, disabled }: SourceSelectorProps) {
  const toggle = (key: SourceKey) => {
    if (disabled) return;
    if (selected.includes(key)) {
      // Don't allow zero sources.
      if (selected.length === 1) return;
      onChange(selected.filter((s) => s !== key));
    } else {
      onChange([...selected, key]);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
          Sources
        </p>
        <p className="text-[11px] text-hcl-muted">
          {selected.length} of {SOURCES.length} selected
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {SOURCES.map(({ key, label, hint, Icon, requiresCredential }) => {
          const credentialed = isCredentialed(key, config);
          const active = selected.includes(key);
          const unavailable = requiresCredential && !credentialed;
          const isLastSelected = active && selected.length === 1;
          const buttonDisabled = disabled || unavailable || isLastSelected;
          return (
            <button
              key={key}
              type="button"
              onClick={() => toggle(key)}
              disabled={buttonDisabled}
              aria-pressed={active}
              title={
                unavailable
                  ? `${hint} — credential not configured on backend`
                  : isLastSelected
                    ? 'At least one source must be selected'
                    : hint
              }
              className={cn(
                'group relative flex items-center gap-2.5 rounded-lg border p-3 text-left transition-all duration-base ease-spring',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                active && !buttonDisabled
                  ? 'border-primary bg-primary/5 shadow-glow-primary'
                  : 'border-border bg-surface',
                !buttonDisabled && !active && 'hover:-translate-y-px hover:bg-surface-muted hover:border-hcl-blue/40',
                buttonDisabled && 'opacity-50 cursor-not-allowed',
                unavailable && 'border-dashed',
              )}
            >
              <span
                className={cn(
                  'flex h-9 w-9 shrink-0 items-center justify-center rounded-md transition-colors',
                  active ? 'bg-primary text-white' : 'bg-surface-muted text-hcl-muted',
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-hcl-navy">{label}</p>
                <p className="truncate text-[10px] text-hcl-muted">
                  {unavailable ? 'Credential missing' : credentialed ? hint.split(' — ')[1] ?? hint : hint}
                </p>
              </div>
              {active && (
                <span
                  aria-hidden
                  className="absolute right-2 top-2 inline-flex h-4 w-4 items-center justify-center rounded-full bg-primary text-white motion-scale-in"
                >
                  <Check className="h-2.5 w-2.5" />
                </span>
              )}
            </button>
          );
        })}
      </div>
      {config && !config.nvd_key_configured && selected.includes('NVD') && (
        <p className="flex items-start gap-1.5 text-[11px] text-hcl-muted">
          <Layers className="h-3 w-3 mt-0.5" aria-hidden />
          <span>
            NVD has no API key configured — public rate limits apply (~10s delay between bursts).
            Add <code className="font-mono">NVD_API_KEY</code> on the backend for faster scans.
          </span>
        </p>
      )}
    </div>
  );
}
