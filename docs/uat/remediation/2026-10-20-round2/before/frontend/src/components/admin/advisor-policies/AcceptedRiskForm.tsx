'use client';

import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  actionableVex,
  lifecycleBuckets,
  type RuleErrors,
} from './policyRules';

export function AcceptedRiskForm({
  rules,
  errors,
  onChange,
}: {
  rules: Record<string, unknown>;
  errors: RuleErrors;
  onChange: (rules: Record<string, unknown>) => void;
}) {
  function update(key: string, value: unknown) {
    onChange({ ...rules, [key]: value });
  }
  const vex = Array.isArray(rules.allowed_actionable_vex_statuses)
    ? rules.allowed_actionable_vex_statuses.map((v) => String(v).toUpperCase())
    : rules.allowed_actionable_vex_statuses === undefined
      ? [...actionableVex]
      : [];
  const lifecycle = Array.isArray(rules.allowed_lifecycle)
    ? rules.allowed_lifecycle.map((v) => String(v).trim().toUpperCase())
    : [];
  const severity = String(rules.max_actionable_severity ?? '')
    .trim()
    .toUpperCase();
  return (
    <div className="space-y-6">
      <div className="grid gap-5 sm:grid-cols-2">
        <Select
          label="Maximum actionable severity"
          value={['LOW', 'MEDIUM'].includes(severity) ? severity : ''}
          onChange={(e) => update('max_actionable_severity', e.target.value)}
          error={errors.max_actionable_severity}
          hint="Only LOW or MEDIUM may qualify. HIGH and CRITICAL are never accepted."
        >
          {!['LOW', 'MEDIUM'].includes(severity) && (
            <option value="" disabled>
              Select LOW or MEDIUM
            </option>
          )}
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
        </Select>
        {(
          [
            [
              'max_cvss_score',
              'Maximum CVSS score',
              'Optional · 0–10. Leave blank for no CVSS limit.',
              'decimal',
            ],
            [
              'max_actionable_vulnerabilities',
              'Maximum actionable vulnerabilities',
              'Optional · Non-negative whole number. Zero permits no actionable vulnerabilities.',
              'numeric',
            ],
            [
              'max_analysis_age_days',
              'Maximum analysis age (days)',
              'Optional · Positive whole number of days. Leave blank for no age limit.',
              'numeric',
            ],
          ] as const
        ).map(([key, label, hint, inputMode]) => (
          <Input
            key={key}
            type="text"
            inputMode={inputMode}
            label={label}
            hint={hint}
            error={errors[key]}
            value={rules[key] == null ? '' : String(rules[key])}
            onChange={(e) => {
              const raw = e.target.value;
              update(
                key,
                raw.trim() === ''
                  ? null
                  : /^-?(?:\d+(?:\.\d+)?|\.\d+)$/.test(raw) &&
                      Number.isFinite(Number(raw))
                    ? Number(raw)
                    : raw,
              );
            }}
          />
        ))}
      </div>
      <fieldset aria-describedby="accepted-vex-hint" className="space-y-3">
        <legend className="text-sm font-semibold text-hcl-navy">
          Allowed actionable VEX statuses
        </legend>
        <p id="accepted-vex-hint" className="text-sm text-hcl-muted">
          Select at least one. Actionable statuses outside this selection
          prevent acceptance.
        </p>
        <div className="flex flex-wrap gap-3">
          {actionableVex.map((value) => (
            <label
              key={value}
              className="flex min-h-11 items-center gap-2 rounded-lg border border-border bg-surface px-3 text-sm"
            >
              <input
                type="checkbox"
                checked={vex.includes(value)}
                onChange={(e) =>
                  update(
                    'allowed_actionable_vex_statuses',
                    e.target.checked
                      ? [...vex, value]
                      : vex.filter((v) => v !== value),
                  )
                }
              />
              {value}
            </label>
          ))}
        </div>
        {errors.allowed_actionable_vex_statuses && (
          <p role="alert" className="text-sm text-red-700 dark:text-red-300">
            {errors.allowed_actionable_vex_statuses}
          </p>
        )}
      </fieldset>
      <fieldset
        aria-describedby="accepted-lifecycle-hint"
        className="space-y-3"
      >
        <legend className="text-sm font-semibold text-hcl-navy">
          Allowed lifecycle
        </legend>
        <p id="accepted-lifecycle-hint" className="text-sm text-hcl-muted">
          Optional. No selection means no lifecycle restriction, matching the
          policy evaluator.
        </p>
        <div className="flex flex-wrap gap-3">
          {lifecycleBuckets.map((value) => (
            <label
              key={value}
              className="flex min-h-11 items-center gap-2 rounded-lg border border-border bg-surface px-3 text-sm"
            >
              <input
                type="checkbox"
                checked={lifecycle.includes(value)}
                onChange={(e) =>
                  update(
                    'allowed_lifecycle',
                    e.target.checked
                      ? [...lifecycle, value]
                      : lifecycle.filter((v) => v !== value),
                  )
                }
              />
              {value}
            </label>
          ))}
        </div>
        {errors.allowed_lifecycle && (
          <p role="alert" className="text-sm text-red-700 dark:text-red-300">
            {errors.allowed_lifecycle}
          </p>
        )}
      </fieldset>
    </div>
  );
}
