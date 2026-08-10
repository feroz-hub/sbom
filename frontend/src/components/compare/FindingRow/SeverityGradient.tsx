'use client';

import type { CveSeverity } from '@/types/cve';

interface Props {
  severity: CveSeverity | null;
}

const FADE_VAR: Record<string, string> = {
  critical: 'var(--severity-critical-fade)',
  high: 'var(--severity-high-fade)',
  medium: 'var(--severity-medium-fade)',
  low: 'var(--severity-low-fade)',
  none: 'var(--severity-unknown-fade)',
  unknown: 'var(--severity-unknown-fade)',
};

/**
 * Decorative left-edge fade tinted by severity. Sits on top of the row's
 * change_kind border-l (which stays as a 4px solid stripe). Together they
 * give two visual axes — change_kind by hue+border, severity by gradient
 * intensity.
 *
 * `aria-hidden` because the chip text is the source of truth for
 * accessibility.
 */
export function SeverityGradient({ severity }: Props) {
  const stop = FADE_VAR[severity ?? 'unknown'] ?? FADE_VAR.unknown;
  return (
    <span
      aria-hidden
      className="pointer-events-none absolute inset-y-0 left-0 w-[60px]"
      style={{
        background: `linear-gradient(to right, ${stop} 0%, transparent 100%)`,
      }}
    />
  );
}
