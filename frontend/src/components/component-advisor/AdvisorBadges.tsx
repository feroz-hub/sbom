/**
 * Secure Component Advisor badges (NFR-SCA-008, WCAG 2.2 AA).
 *
 * Every badge carries an icon *and* a text label and an aria-label, so risk,
 * lifecycle, confidence and check results are never conveyed by colour alone.
 */

import {
  AlertTriangle,
  BadgeCheck,
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock,
  Eye,
  HelpCircle,
  Info,
  ShieldAlert,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import type {
  AdvisorCheckResult,
  AdvisorConfidence,
  AdvisorLifecycleBucket,
  AdvisorPurposeField,
  AdvisorRiskClassification,
} from '@/types/componentAdvisor';
import { CHECK_LABELS, CONFIDENCE_LABELS, LIFECYCLE_LABELS, RISK_LABELS } from './labels';

type Variant = 'default' | 'success' | 'error' | 'warning' | 'info' | 'gray';

function IconBadge({ icon: Icon, variant, label, ariaLabel }: { icon: LucideIcon; variant: Variant; label: string; ariaLabel: string }) {
  return (
    <Badge variant={variant}>
      <span className="inline-flex items-center gap-1" aria-label={ariaLabel} role="img">
        <Icon className="h-3 w-3" aria-hidden />
        <span aria-hidden>{label}</span>
      </span>
    </Badge>
  );
}

const RISK_STYLE: Record<AdvisorRiskClassification, { icon: LucideIcon; variant: Variant }> = {
  CRITICAL: { icon: ShieldAlert, variant: 'error' },
  HIGH: { icon: ShieldAlert, variant: 'error' },
  MEDIUM: { icon: AlertTriangle, variant: 'warning' },
  LOW: { icon: Info, variant: 'info' },
  INFORMATIONAL: { icon: Info, variant: 'gray' },
  ACCEPTED_RISK: { icon: BadgeCheck, variant: 'info' },
  REVIEW_REQUIRED: { icon: Eye, variant: 'warning' },
  UNKNOWN: { icon: HelpCircle, variant: 'gray' },
  NO_KNOWN_ACTIONABLE_VULNERABILITIES: { icon: CheckCircle2, variant: 'success' },
};

export function RiskBadge({ classification }: { classification: AdvisorRiskClassification }) {
  const style = RISK_STYLE[classification] ?? RISK_STYLE.UNKNOWN;
  const label = RISK_LABELS[classification] ?? classification;
  return <IconBadge icon={style.icon} variant={style.variant} label={label} ariaLabel={`Risk: ${label}`} />;
}

const LIFECYCLE_STYLE: Record<AdvisorLifecycleBucket, { icon: LucideIcon; variant: Variant }> = {
  SUPPORTED: { icon: CheckCircle2, variant: 'success' },
  MAINTENANCE: { icon: Clock, variant: 'warning' },
  EOS: { icon: AlertTriangle, variant: 'warning' },
  EOL: { icon: Ban, variant: 'error' },
  UNKNOWN: { icon: CircleDashed, variant: 'gray' },
};

export function LifecycleBadge({ bucket }: { bucket: AdvisorLifecycleBucket }) {
  const style = LIFECYCLE_STYLE[bucket] ?? LIFECYCLE_STYLE.UNKNOWN;
  const label = LIFECYCLE_LABELS[bucket] ?? bucket;
  return <IconBadge icon={style.icon} variant={style.variant} label={label} ariaLabel={`Lifecycle: ${label}`} />;
}

const CONFIDENCE_STYLE: Record<AdvisorConfidence, { icon: LucideIcon; variant: Variant }> = {
  HIGH: { icon: CheckCircle2, variant: 'success' },
  MEDIUM: { icon: Info, variant: 'info' },
  LOW: { icon: AlertTriangle, variant: 'warning' },
  INSUFFICIENT_EVIDENCE: { icon: HelpCircle, variant: 'gray' },
  NOT_EVALUATED: { icon: CircleDashed, variant: 'gray' },
};

export function ConfidenceBadge({ confidence }: { confidence: AdvisorConfidence }) {
  const style = CONFIDENCE_STYLE[confidence] ?? CONFIDENCE_STYLE.NOT_EVALUATED;
  const label = CONFIDENCE_LABELS[confidence] ?? confidence;
  return <IconBadge icon={style.icon} variant={style.variant} label={label} ariaLabel={`Confidence: ${label}`} />;
}

const CHECK_STYLE: Record<AdvisorCheckResult, { icon: LucideIcon; variant: Variant }> = {
  PASS: { icon: CheckCircle2, variant: 'success' },
  FAIL: { icon: Ban, variant: 'error' },
  REVIEW_REQUIRED: { icon: Eye, variant: 'warning' },
  UNKNOWN: { icon: HelpCircle, variant: 'gray' },
};

export function CheckResultBadge({ result, blocking = false }: { result: AdvisorCheckResult; blocking?: boolean }) {
  const style = CHECK_STYLE[result] ?? CHECK_STYLE.UNKNOWN;
  const label = `${CHECK_LABELS[result] ?? result}${blocking ? ' (blocking)' : ''}`;
  return <IconBadge icon={style.icon} variant={style.variant} label={label} ariaLabel={`Check result: ${label}`} />;
}

/** Provenance chip; AI-assisted metadata is visually and structurally distinct (FR-SCA-009). */
export function ProvenanceBadge({ field }: { field: AdvisorPurposeField }) {
  if (field.ai_assisted) {
    return (
      <IconBadge icon={Sparkles} variant="warning" label={`AI-assisted · ${field.confidence.toLowerCase()} confidence`}
        ariaLabel={`AI-assisted metadata, ${field.confidence.toLowerCase()} confidence; not authoritative`} />
    );
  }
  const sourceLabels: Record<AdvisorPurposeField['source'], string> = {
    SBOM: 'From SBOM', PACKAGE: 'Package metadata', CURATED: 'Curated', AI: 'AI-assisted',
  };
  const source = sourceLabels[field.source] ?? field.source;
  return <IconBadge icon={Info} variant="gray" label={source} ariaLabel={`Source: ${source}`} />;
}
