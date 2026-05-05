'use client';

import { Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  useAiCredentialSettings,
  useUpdateAiCredentialSettings,
} from '@/hooks/useAiCredentials';

interface BudgetCapsFormProps {
  className?: string;
}

/**
 * Phase 3 §3.6 — editable budget caps + kill-switch toggle.
 *
 * Validation: per_request ≤ per_scan ≤ per_day. Backend enforces the
 * same; frontend mirrors so the user sees the error inline before
 * round-tripping.
 */
export function BudgetCapsForm({ className }: BudgetCapsFormProps) {
  const { data: settings, isLoading } = useAiCredentialSettings();
  const updateMut = useUpdateAiCredentialSettings();

  const [perRequest, setPerRequest] = useState('0.10');
  const [perScan, setPerScan] = useState('5.00');
  const [perDay, setPerDay] = useState('5.00');
  const [killSwitch, setKillSwitch] = useState(false);
  const [featureEnabled, setFeatureEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!settings) return;
    setPerRequest(settings.budget_per_request_usd.toFixed(2));
    setPerScan(settings.budget_per_scan_usd.toFixed(2));
    setPerDay(settings.budget_daily_usd.toFixed(2));
    setKillSwitch(settings.kill_switch_active);
    setFeatureEnabled(settings.feature_enabled);
  }, [settings?.updated_at]);  // eslint-disable-line react-hooks/exhaustive-deps

  const valid = (() => {
    const a = Number.parseFloat(perRequest);
    const b = Number.parseFloat(perScan);
    const c = Number.parseFloat(perDay);
    if ([a, b, c].some((n) => Number.isNaN(n) || n < 0)) {
      return 'All caps must be non-negative numbers.';
    }
    if (!(a <= b && b <= c)) {
      return 'Caps must satisfy per_request ≤ per_scan ≤ per_day.';
    }
    return null;
  })();

  const handleSave = () => {
    setSaved(false);
    if (valid) {
      setError(valid);
      return;
    }
    setError(null);
    updateMut.mutate(
      {
        budget_per_request_usd: Number.parseFloat(perRequest),
        budget_per_scan_usd: Number.parseFloat(perScan),
        budget_daily_usd: Number.parseFloat(perDay),
        kill_switch_active: killSwitch,
        feature_enabled: featureEnabled,
      },
      {
        onSuccess: () => setSaved(true),
        onError: (err) => setError(err.message ?? 'Save failed'),
      },
    );
  };

  return (
    <section
      className={`rounded-lg border border-border-subtle bg-surface p-4 ${className ?? ''}`}
      aria-labelledby="ai-budget-caps-heading"
    >
      <h2 id="ai-budget-caps-heading" className="mb-3 text-base font-semibold text-hcl-navy">
        Budget caps
      </h2>

      {isLoading ? (
        <p className="text-sm text-hcl-muted">Loading…</p>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <FormRow id="cap-per-request" label="Per request" value={perRequest} onChange={setPerRequest} />
            <FormRow id="cap-per-scan" label="Per scan" value={perScan} onChange={setPerScan} />
            <FormRow id="cap-per-day" label="Per day total" value={perDay} onChange={setPerDay} />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm text-hcl-navy">
              <input
                type="checkbox"
                checked={featureEnabled}
                onChange={(e) => setFeatureEnabled(e.target.checked)}
              />
              AI fixes feature enabled
            </label>
            <label className="flex items-center gap-2 text-sm text-red-700">
              <input
                type="checkbox"
                checked={killSwitch}
                onChange={(e) => setKillSwitch(e.target.checked)}
              />
              Kill switch active (immediately blocks every AI call)
            </label>
          </div>

          {error ? (
            <p
              role="alert"
              className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800"
            >
              {error}
            </p>
          ) : null}
          {saved ? (
            <p
              role="status"
              className="mt-3 rounded-md border border-emerald-200 bg-emerald-50 p-2 text-sm text-emerald-800"
            >
              Saved.
            </p>
          ) : null}

          <div className="mt-4 flex items-center justify-end">
            <button
              type="button"
              onClick={handleSave}
              disabled={updateMut.isPending || valid !== null}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white shadow-elev-1 hover:bg-hcl-dark disabled:cursor-not-allowed disabled:opacity-50"
            >
              {updateMut.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              ) : null}
              Save
            </button>
          </div>
        </>
      )}
    </section>
  );
}


interface FormRowProps {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
}


function FormRow({ id, label, value, onChange }: FormRowProps) {
  return (
    <div>
      <label htmlFor={id} className="text-xs font-medium text-hcl-navy">
        {label}
      </label>
      <div className="relative mt-1">
        <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-2 text-hcl-muted">
          $
        </span>
        <input
          id={id}
          type="number"
          min="0"
          step="0.01"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded-md border border-border-subtle bg-surface py-2 pl-6 pr-3 font-metric tabular-nums text-sm"
        />
      </div>
    </div>
  );
}
