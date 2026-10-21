'use client';

import { useEffect, useId, useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, FileCode2, Info, ShieldCheck } from 'lucide-react';
import { useMutationScope } from '@/hooks/useMutationScope';
import { invalidateAdvisorPolicySurfaces } from '@/lib/queryInvalidation';
import { ApiError } from '@/lib/api';
import {
  publishAdvisorPolicy,
  type AdvisorPolicyState,
  type AdvisorPolicyStatus,
} from '@/lib/advisorPolicyApi';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { AcceptedRiskForm } from './AcceptedRiskForm';
import {
  parseRules,
  summarizeRules,
  validateRules,
  type PolicyDefinition,
} from './policyRules';
import styles from './policies.module.css';
import { PolicyHistory } from './PolicyHistory';

function initialDraft(
  state: AdvisorPolicyState,
  tenantId: (string | number) | null,
  definition: PolicyDefinition,
) {
  const owned =
    tenantId === null ? state.platform_default : state.tenant_override;
  const rules = JSON.stringify(
    owned?.status === 'ACTIVE'
      ? owned.rules
      : (state.effective?.rules ?? definition.example),
    null,
    2,
  );
  return {
    base: state,
    status:
      owned?.status ??
      ((tenantId === null ? 'DISABLED' : 'INHERIT') as AdvisorPolicyStatus),
    rules,
    originalRules: rules,
    originalStatus:
      owned?.status ?? (tenantId === null ? 'DISABLED' : 'INHERIT'),
    reason: '',
  };
}
function modeDescription(
  status: AdvisorPolicyStatus,
  platform: boolean,
  scoring: boolean,
) {
  if (status === 'ACTIVE')
    return platform
      ? 'Publish platform rules for tenants that inherit this policy.'
      : 'Use these rules only for this tenant, replacing the platform default.';
  if (status === 'INHERIT')
    return `Withdraw this tenant override and use an active platform default when available.${scoring ? ' With no applicable policy, scoring uses built-in defaults.' : ' With no active platform policy, no component qualifies through this policy.'}`;
  return `${platform ? 'Disable the platform default. Active tenant overrides remain independent.' : 'Disable this policy for this tenant and block platform inheritance.'} ${scoring ? 'Scoring uses built-in defaults when no policy applies.' : 'No component qualifies through this disabled policy.'}`;
}

export function PolicyEditor({
  tenantId,
  definition,
  state,
  canUpdate,
  reload,
}: {
  tenantId: (string | number) | null;
  definition: PolicyDefinition;
  state: AdvisorPolicyState;
  canUpdate: boolean;
  reload: () => Promise<AdvisorPolicyState>;
}) {
  const client = useQueryClient();
  const mutationScope = useMutationScope();
  const [draft, setDraft] = useState(() =>
    initialDraft(state, tenantId, definition),
  );
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const dirty =
    draft.rules !== draft.originalRules ||
    draft.status !== draft.originalStatus ||
    draft.reason !== '';
  // Background reads may update the published summary but must never overwrite local edits or their concurrency token.
  useEffect(() => {
    if (!dirty && !conflict && !confirm)
      setDraft(initialDraft(state, tenantId, definition));
  }, [state, tenantId, definition, dirty, conflict, confirm]);
  const parsed = parseRules(draft.rules);
  const errors = parsed.rules
    ? validateRules(definition.kind, parsed.rules)
    : {};
  const invalid =
    draft.status === 'ACTIVE' &&
    (parsed.error || Object.keys(errors).length > 0);
  const reasonError = !draft.reason.trim()
    ? 'Enter a reason for this change.'
    : draft.reason.trim().length > 2000
      ? 'Reason must be at most 2000 characters.'
      : '';
  const owned =
    tenantId === null ? state.platform_default : state.tenant_override;
  const disabled = !canUpdate || saving || reloading || conflict;
  function changeRules(text: string) {
    setDraft((d) => ({ ...d, rules: text }));
    setSaved(false);
  }
  function review(event: FormEvent) {
    event.preventDefault();
    setAttempted(true);
    setSaved(false);
    setError('');
    if (!canUpdate || disabled || invalid || reasonError) return;
    setConfirm(true);
  }
  async function publish() {
    if (!canUpdate || disabled || invalid || reasonError || !confirm) return;
    const isCurrent = mutationScope.capture();
    if (!isCurrent()) return;
    setSaving(true);
    setError('');
    try {
      const result = await publishAdvisorPolicy(tenantId, definition.kind, {
        status: draft.status,
        rules: draft.status === 'ACTIVE' ? parsed.rules : null,
        reason: draft.reason.trim(),
        row_version: draft.base.row_version,
      });
      if (!isCurrent()) return;
      setDraft(initialDraft(result, tenantId, definition));
      setSaved(true);
      setConfirm(false);
      setAttempted(false);
      client.setQueryData(
        ['advisor-policy', tenantId, definition.kind],
        result,
      );
      await Promise.all([
        client.invalidateQueries({
          queryKey: ['advisor-policy-history', tenantId, definition.kind],
        }),
        invalidateAdvisorPolicySurfaces(client, tenantId),
      ]);
    } catch (err) {
      if (!isCurrent()) return;
      setConfirm(false);
      if (err instanceof ApiError && err.status === 409) {
        setConflict(true);
        setError(
          'Another administrator changed this policy. Reload the latest policy before publishing again.',
        );
      } else
        setError(
          err instanceof Error ? err.message : 'Unable to publish policy.',
        );
    } finally {
      if (isCurrent()) setSaving(false);
    }
  }
  async function discardAndReload() {
    const isCurrent = mutationScope.capture();
    setReloading(true);
    setError('');
    try {
      const latest = await reload();
      if (!isCurrent()) return;
      setDraft(initialDraft(latest, tenantId, definition));
      setConflict(false);
      setAttempted(false);
      setSaved(false);
    } catch (err) {
      if (isCurrent())
        setError(
          err instanceof Error ? err.message : 'Unable to reload policy.',
        );
    } finally {
      if (isCurrent()) setReloading(false);
    }
  }
  return (
    <div className="space-y-5">
      <section
        aria-label={`${definition.title} published configuration`}
        className="rounded-xl border border-border bg-surface p-5 sm:p-6"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <ShieldCheck className="h-5 w-5 text-hcl-blue" aria-hidden />
            Published configuration
          </h2>
          <Badge variant={state.effective ? 'success' : 'gray'}>
            {state.effective
              ? 'ACTIVE'
              : definition.kind === 'scoring'
                ? 'Built-in defaults'
                : 'No effective policy'}
          </Badge>
        </div>
        <dl className="mt-5 grid gap-4 sm:grid-cols-3">
          <div>
            <dt className="text-sm text-hcl-muted">Effective source</dt>
            <dd className="mt-1 font-medium">
              {state.effective
                ? `${state.effective.scope === 'PLATFORM' ? 'Platform default' : 'Tenant override'}`
                : definition.kind === 'scoring'
                  ? 'Built-in scoring defaults'
                  : 'None'}
            </dd>
          </div>
          <div>
            <dt className="text-sm text-hcl-muted">Effective version</dt>
            <dd className="mt-1 font-medium">
              {state.effective ? `v${state.effective.version}` : '—'}
            </dd>
          </div>
          <div>
            <dt className="text-sm text-hcl-muted">
              Published mode in this scope
            </dt>
            <dd className="mt-1 font-medium">
              {owned?.status ??
                (tenantId === null ? 'Not configured' : 'INHERIT')}
              {owned ? ` · v${owned.version}` : ''}
            </dd>
          </div>
        </dl>
        {state.effective && (
          <>
            <p className="mt-4 break-words border-t border-border pt-4 text-sm text-hcl-muted">
              {summarizeRules(definition.kind, state.effective.rules)}
            </p>
            <details className="mt-3">
              <summary className="cursor-pointer rounded py-2 text-sm font-medium">
                Effective rules
              </summary>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-surface-muted p-4 text-xs">
                {JSON.stringify(state.effective.rules, null, 2)}
              </pre>
            </details>
          </>
        )}
      </section>
      <form
        noValidate
        onSubmit={review}
        className="rounded-xl border border-border bg-surface p-5 sm:p-6"
      >
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold">
              {canUpdate ? 'Policy configuration' : 'Configuration details'}
            </h2>
            <p className="mt-1 text-sm text-hcl-muted">
              {canUpdate
                ? 'Changes stay in this browser until you confirm publication.'
                : 'Published settings are available for inspection.'}
            </p>
          </div>
          {dirty && canUpdate && (
            <Badge variant="warning">Unsaved changes · local only</Badge>
          )}
        </div>
        {!canUpdate && (
          <p className="mb-5 rounded-lg border border-border bg-surface-muted p-3 text-sm">
            Read-only access. A {tenantId === null ? 'Platform' : 'Tenant'}{' '}
            Admin with update permission can publish policy changes.
          </p>
        )}
        {dirty && state.row_version !== draft.base.row_version && (
          <p
            role="status"
            className="mb-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200"
          >
            A newer published policy is available. Your local changes and
            original concurrency token have been kept.
          </p>
        )}
        <fieldset disabled={disabled} className="min-w-0 space-y-6">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <Select
              label="Policy mode"
              aria-label={`${definition.label} policy mode`}
              value={draft.status}
              onChange={(e) => {
                setDraft((d) => ({
                  ...d,
                  status: e.target.value as AdvisorPolicyStatus,
                }));
                setSaved(false);
              }}
            >
              {tenantId !== null && (
                <option value="INHERIT">Inherit platform default</option>
              )}
              <option value="ACTIVE">
                {tenantId === null
                  ? 'Use platform default'
                  : 'Use tenant policy'}
              </option>
              <option value="DISABLED">
                {tenantId === null
                  ? 'Disable platform default'
                  : 'Disable policy for this tenant'}
              </option>
            </Select>
            <p className="flex items-start gap-2 rounded-lg border border-border bg-surface-muted p-3 text-sm text-hcl-muted">
              <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              {modeDescription(
                draft.status,
                tenantId === null,
                definition.kind === 'scoring',
              )}
            </p>
          </div>
          {draft.status === 'ACTIVE' && (
            <>
              {definition.kind === 'accepted-risk' &&
                (parsed.rules ? (
                  <AcceptedRiskForm
                    rules={parsed.rules}
                    errors={errors}
                    onChange={(rules) =>
                      changeRules(JSON.stringify(rules, null, 2))
                    }
                  />
                ) : (
                  <p className="rounded-lg border border-border bg-surface-muted p-4 text-sm">
                    The visual editor is paused while JSON is invalid. Correct
                    it in Advanced JSON to continue; your text has been
                    preserved.
                  </p>
                ))}
              {definition.kind === 'accepted-risk' ? (
                <details className="rounded-lg border border-border p-4">
                  <summary className="cursor-pointer rounded font-medium">
                    <FileCode2 className="mr-2 inline h-4 w-4" aria-hidden />
                    Advanced JSON
                  </summary>
                  <p className="my-3 text-sm text-hcl-muted">
                    Edit the same rules used by the form. Invalid or unknown
                    fields remain in your text and block publication until
                    corrected.
                  </p>
                  <JsonRules
                    label={definition.label}
                    value={draft.rules}
                    onChange={changeRules}
                    error={parsed.error}
                  />
                </details>
              ) : (
                <section className="space-y-3">
                  <h3 className="font-medium">Policy rules</h3>
                  <p className="text-sm text-hcl-muted">
                    {parsed.rules
                      ? summarizeRules(definition.kind, parsed.rules)
                      : 'Correct the JSON to see a summary.'}
                  </p>
                  <p className="text-sm text-hcl-muted">
                    Use the existing backend rule names. This editor validates
                    the document before publication; the server validates it
                    again.
                  </p>
                  <JsonRules
                    label={definition.label}
                    value={draft.rules}
                    onChange={changeRules}
                    error={parsed.error}
                  />
                </section>
              )}
              {Object.keys(errors).length > 0 && (
                <div
                  role="alert"
                  className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
                >
                  <p className="font-medium">
                    Correct the policy rules before publishing.
                  </p>
                  <ul className="mt-2 list-inside list-disc">
                    {Object.entries(errors).map(([key, message]) => (
                      <li key={key}>{message}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
          {canUpdate && (
            <div className="space-y-4 border-t border-border pt-5">
              <Input
                label="Reason for change"
                aria-label={`${definition.label} reason`}
                required
                maxLength={2000}
                value={draft.reason}
                onChange={(e) => {
                  setDraft((d) => ({ ...d, reason: e.target.value }));
                  setSaved(false);
                }}
                hint="Required for the immutable version history. Maximum 2000 characters."
                error={attempted ? reasonError : undefined}
              />
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-xs text-hcl-muted">
                  {draft.reason.length.toLocaleString()} / 2,000 characters
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="secondary"
                    disabled={!dirty}
                    onClick={() => {
                      setDraft(initialDraft(draft.base, tenantId, definition));
                      setAttempted(false);
                      setSaved(false);
                      setError('');
                    }}
                  >
                    Discard local changes
                  </Button>
                  <Button
                    type="submit"
                    loading={saving}
                    loadingLabel="Publishing policy"
                  >
                    {saving ? 'Publishing…' : 'Publish policy version'}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </fieldset>
        {error && (
          <p
            role="alert"
            className="mt-4 rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
          >
            {error}
          </p>
        )}
        {conflict && (
          <Button
            className="mt-3"
            variant="secondary"
            loading={reloading}
            onClick={discardAndReload}
          >
            Reload latest policy (discard draft)
          </Button>
        )}
        {saved && (
          <p role="status" className="mt-4 flex items-center gap-2 text-sm">
            <CheckCircle2
              className="h-4 w-4 text-emerald-700 dark:text-emerald-300"
              aria-hidden
            />
            Policy version published.
          </p>
        )}
      </form>
      <PolicyHistory tenantId={tenantId} kind={definition.kind} />
      <Dialog
        open={confirm}
        onClose={() => {
          if (!saving) setConfirm(false);
        }}
        title="Publish policy version?"
        maxWidth="xl"
        dismissOnBackdrop={!saving}
        footer={
          <DialogFooter>
            <Button
              variant="secondary"
              disabled={saving}
              onClick={() => setConfirm(false)}
            >
              Cancel
            </Button>
            <Button
              disabled={
                !canUpdate ||
                Boolean(invalid) ||
                Boolean(reasonError) ||
                conflict
              }
              loading={saving}
              onClick={publish}
            >
              Confirm publication
            </Button>
          </DialogFooter>
        }
      >
        <DialogBody className={styles.page}>
          <div className="space-y-4 text-sm">
            <p>
              Publish <strong>{definition.title}</strong> for{' '}
              <strong>
                {tenantId === null ? 'platform defaults' : 'this tenant'}
              </strong>
              ?
            </p>
            <dl className="space-y-3">
              <div>
                <dt className="text-hcl-muted">Mode change</dt>
                <dd className="font-medium">
                  {draft.originalStatus} → {draft.status}
                </dd>
              </div>
              <div>
                <dt className="text-hcl-muted">Effect</dt>
                <dd>
                  {modeDescription(
                    draft.status,
                    tenantId === null,
                    definition.kind === 'scoring',
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-hcl-muted">Reason</dt>
                <dd className="whitespace-pre-wrap break-words">
                  {draft.reason.trim()}
                </dd>
              </div>
            </dl>
            {draft.status === 'ACTIVE' && (
              <>
                <p>
                  {draft.rules === draft.originalRules
                    ? 'Rule values are unchanged.'
                    : 'Proposed rules are shown below. Publishing creates an immutable version.'}
                </p>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-surface-muted p-4 text-xs">
                  {draft.rules}
                </pre>
              </>
            )}
          </div>
        </DialogBody>
      </Dialog>
    </div>
  );
}

function JsonRules({
  label,
  value,
  onChange,
  error,
}: {
  label: string;
  value: string;
  onChange: (text: string) => void;
  error: string | null;
}) {
  const errorId = useId();
  return (
    <label className="block space-y-2 text-sm font-medium">
      Rules (JSON)
      <textarea
        aria-label={`${label} rules`}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? errorId : undefined}
        className="min-h-64 w-full resize-y rounded-lg border border-border bg-surface-muted p-4 font-mono text-sm leading-6 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
      />
      {error && (
        <span
          id={errorId}
          role="alert"
          className="block text-sm text-red-700 dark:text-red-300"
        >
          {error}
        </span>
      )}
    </label>
  );
}
