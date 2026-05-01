/**
 * Adaptive hero headline — the single most-visible piece of copy on the
 * dashboard. The state itself comes from the server (`/dashboard/posture`
 * computes it once with strict precedence so every consumer agrees); this
 * file is the rendering map: state + data → headline + sub-line + tone.
 *
 * Copy is locked in `docs/dashboard-redesign.md` §2.2. If you change a
 * string here, update that table in the same PR — the doc is the contract
 * we read before reviewing copy changes.
 *
 * Pluralization uses `pluralize()` from `./pluralize`; the helper returns
 * `"1 finding"` / `"2 findings"` so we never read "1 findings" anywhere.
 */

import { pluralize } from './pluralize';
import type { HeadlineState } from '@/types';

/**
 * Tone is the sole input the visual layer needs from a headline rule.
 * `success` — emerald; `info` — sky; `warning` — orange; `danger` — red;
 * `neutral` — slate / hcl-muted. Mapping to actual classes lives in the
 * components that consume this output, not here, so a Storybook story can
 * preview just the copy without dragging in Tailwind classes.
 */
export type HeadlineTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger';

export interface HeadlineCopy {
  headline: string;
  subline: string;
  tone: HeadlineTone;
}

/**
 * Inputs the rules look at. All fields optional so a partially-loaded
 * payload still produces something renderable (the loading skeleton is a
 * separate component; this map should never throw).
 */
export interface HeadlineInputs {
  total_sboms?: number;
  total_findings?: number;
  critical?: number;
  high?: number;
  kev_count?: number;
}

/**
 * Render `headline` + `subline` + `tone` for a given posture state.
 *
 * The function is total — `state` is a finite union and TypeScript's
 * exhaustiveness check forces us to handle each case explicitly. Tests
 * cover the pluralization branches; if someone adds a new state to the
 * union without updating this map, the type checker fails the build.
 */
export function computeHeadlineCopy(
  state: HeadlineState,
  data: HeadlineInputs,
): HeadlineCopy {
  const sbomCount = data.total_sboms ?? 0;
  const findingCount = data.total_findings ?? 0;
  const critical = data.critical ?? 0;
  const high = data.high ?? 0;
  const kev = data.kev_count ?? 0;

  switch (state) {
    case 'no_data':
      return {
        headline: 'No SBOMs uploaded yet.',
        subline:
          'Upload your first SBOM to see your security posture here.',
        tone: 'neutral',
      };

    case 'clean':
      return {
        headline: `All clear across ${pluralize(sbomCount, 'SBOM', 'SBOMs')}.`,
        subline:
          'No critical or high-severity findings in your portfolio right now.',
        tone: 'success',
      };

    case 'kev_present': {
      // KEV always wins over critical/high — actively-exploited vulns are a
      // different mental category, not a higher severity tier.
      const noun = kev === 1 ? 'finding needs' : 'findings need';
      return {
        headline: `${kev.toLocaleString()} actively exploited ${noun} attention.`,
        subline:
          "These are listed in CISA's Known Exploited Vulnerabilities catalog. Prioritize remediation.",
        tone: 'danger',
      };
    }

    case 'criticals_no_kev':
      return {
        headline: `${pluralize(critical, 'critical finding', 'critical findings')} across ${pluralize(sbomCount, 'SBOM', 'SBOMs')}.`,
        subline:
          'None are in CISA KEV. Review and prioritize by exploitability.',
        tone: 'warning',
      };

    case 'high_only':
      return {
        headline: `${pluralize(high, 'high-severity finding', 'high-severity findings')} to review.`,
        subline: 'No criticals; manageable backlog.',
        tone: 'info',
      };

    case 'low_volume':
      return {
        headline: `${pluralize(findingCount, 'finding', 'findings')}, none critical or high.`,
        subline: 'Stable posture — schedule routine remediation.',
        tone: 'neutral',
      };

    default: {
      // Exhaustiveness guard. If a new HeadlineState lands without a
      // case here, the next line fails to compile.
      const _exhaustive: never = state;
      void _exhaustive;
      return {
        headline: '—',
        subline: '',
        tone: 'neutral',
      };
    }
  }
}

/**
 * Tone → Tailwind class. Kept here (not in the component) so Storybook
 * stories that render copy in isolation can still call it. Light + dark
 * mode parity is built in: each tone references both shades via the
 * `dark:` variant, matching the existing pattern at
 * `HeroRiskPulse.tsx:60-92` for consistency.
 */
export function toneToHeadlineClass(tone: HeadlineTone): string {
  switch (tone) {
    case 'success':
      return 'text-emerald-700 dark:text-emerald-300';
    case 'info':
      return 'text-sky-700 dark:text-sky-300';
    case 'warning':
      return 'text-orange-700 dark:text-orange-300';
    case 'danger':
      return 'text-red-700 dark:text-red-300';
    case 'neutral':
    default:
      return 'text-hcl-navy';
  }
}

/**
 * Tone → ambient-glow class for the hero card decoration. Same color
 * family as the headline, lower opacity so it doesn't compete.
 */
export function toneToAmbientClass(tone: HeadlineTone): string {
  switch (tone) {
    case 'success':
      return 'bg-emerald-300/30';
    case 'info':
      return 'bg-sky-300/30';
    case 'warning':
      return 'bg-orange-400/30';
    case 'danger':
      return 'bg-red-400/30';
    case 'neutral':
    default:
      return 'bg-slate-300/20';
  }
}
