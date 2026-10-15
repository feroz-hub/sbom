'use client';

import { useEffect, useRef, useState } from 'react';
import { KeyRound, Save, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { getApiErrorMessage } from '@/lib/notifications';
import type { LifecycleProviderConfig, LifecycleProviderUpdatePayload } from '@/types';

interface Props {
  provider: LifecycleProviderConfig;
  credentialConfigured?: boolean;
  onClose: () => void;
  onSave: (key: string, payload: LifecycleProviderUpdatePayload) => Promise<void>;
  onSaveSecret: (key: string, name: string, value: string) => Promise<void>;
  onDeleteSecret: (key: string, name: string) => Promise<void>;
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  readOnly?: boolean;
  inherited?: boolean;
  scope?: 'platform' | 'tenant';
}
const inputClass = 'mt-1.5 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-hcl-navy outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue disabled:bg-surface-muted disabled:text-hcl-muted';
function initialDraft(p: LifecycleProviderConfig) {
  return { enabled: p.enabled, priority: String(p.priority), endpoint: p.base_url ?? '', feeds: p.feed_urls.join('\n'),
    timeout: String(p.timeout_seconds), retries: String(p.max_retries), breaker: p.circuit_breaker_enabled,
    known: p.cache_ttl.known_days?.toString() ?? '', unknown: p.cache_ttl.unknown_hours?.toString() ?? '',
    failure: p.cache_ttl.failure_minutes?.toString() ?? '', deprecated: p.cache_ttl.deprecated_days?.toString() ?? '',
    config: JSON.stringify(p.config ?? {}, null, 2) };
}

export function LifecycleProviderForm({ provider, credentialConfigured = provider.has_secret, onSave, onSaveSecret, onDeleteSecret, onDirtyChange, saving = false, readOnly = false, inherited = false, scope = 'platform' }: Props) {
  const [draft, setDraft] = useState(() => initialDraft(provider));
  const [saved, setSaved] = useState(() => initialDraft(provider));
  const [secret, setSecret] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saveError, setSaveError] = useState('');
  const [notice, setNotice] = useState('');
  const [pending, setPending] = useState(false);
  const [credentialPending, setCredentialPending] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const lock = useRef(false);
  const credentialLock = useRef(false);
  const caps = provider.capabilities;
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved) || !!secret || (inherited && !readOnly);
  const busy = saving || pending;
  const set = <K extends keyof typeof draft>(key: K, value: typeof draft[K]) => { setDraft(prev => ({ ...prev, [key]: value })); setNotice(''); };
  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => {
    if (!dirty) return;
    const guard = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', guard);
    return () => window.removeEventListener('beforeunload', guard);
  }, [dirty]);

  let parsed: Record<string, unknown> | null = null;
  try { const value = JSON.parse(draft.config); if (value && typeof value === 'object' && !Array.isArray(value)) parsed = value; } catch { /* Preserve the exact advanced draft. */ }
  const validate = () => {
    const next: Record<string, string> = {};
    const number = (key: keyof typeof draft, min: number, max = Number.MAX_SAFE_INTEGER, optional = false) => {
      const value = String(draft[key]);
      if (optional && !value.trim()) return;
      if (!value.trim() || !Number.isInteger(Number(value)) || Number(value) < min || Number(value) > max) next[key] = `Enter a whole number from ${min} to ${max === Number.MAX_SAFE_INTEGER ? 'the supported limit' : max}.`;
    };
    number('priority', 1, 1000);
    if (caps?.network) { number('timeout', 1, 60); number('retries', 0, 10); }
    for (const key of ['known', 'unknown', 'failure', 'deprecated'] as const) number(key, 1, undefined, true);
    const validUrl = (value: string) => { try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash; } catch { return false; } };
    if (caps?.editable_endpoint && draft.endpoint.trim() && !validUrl(draft.endpoint.trim())) next.endpoint = 'Use an HTTPS URL without credentials, query parameters or fragments.';
    if (caps?.feed_urls && ((draft.enabled && !draft.feeds.trim()) || draft.feeds.split('\n').filter(v => v.trim()).some(v => !validUrl(v.trim())))) next.feeds = 'Add approved HTTPS feed URLs, one per line.';
    if (caps?.config_fields.length && !parsed) next.config = 'Configuration must be a valid JSON object. Your draft has been preserved.';
    if (caps?.config_fields.includes('db_path') && parsed && draft.enabled && !String(parsed?.db_path ?? '').trim()) next.config = 'Enter a readable lifecycle database path.';
    setErrors(next);
    return Object.keys(next).length === 0;
  };
  const save = async (confirmed = false) => {
    if (readOnly || lock.current || !validate()) return;
    if (scope === 'platform' && provider.enabled && !draft.enabled && !confirmed) { setConfirmDisable(true); return; }
    lock.current = true; setPending(true); setSaveError(''); setConfirmDisable(false);
    const nullable = (value: string) => value.trim() ? Number(value) : null;
    try {
      await onSave(provider.provider_key, { enabled: draft.enabled, priority: Number(draft.priority),
        ...(caps?.editable_endpoint ? { base_url: draft.endpoint.trim() || null } : {}),
        ...(caps?.feed_urls ? { feed_urls: draft.feeds.split('\n').map(v => v.trim()).filter(Boolean) } : {}),
        ...(caps?.config_fields.length ? { config: parsed! } : {}),
        ...(caps?.network ? { timeout_seconds: Number(draft.timeout), max_retries: Number(draft.retries), circuit_breaker_enabled: draft.breaker } : {}),
        cache_ttl_known_days: nullable(draft.known), cache_ttl_unknown_hours: nullable(draft.unknown), cache_ttl_failure_minutes: nullable(draft.failure), cache_ttl_deprecated_days: nullable(draft.deprecated) });
      setSaved({ ...draft }); setNotice('Changes saved.');
    } catch (error) { setSaveError(getApiErrorMessage(error, 'Changes could not be saved. Your draft is preserved.')); }
    finally { lock.current = false; setPending(false); }
  };
  const credentialAction = async (clear = false) => {
    if (credentialLock.current || !caps?.secret_name || readOnly || inherited) return;
    credentialLock.current = true; setCredentialPending(true); setSaveError('');
    try {
      if (clear) await onDeleteSecret(provider.provider_key, caps.secret_name);
      else await onSaveSecret(provider.provider_key, caps.secret_name, secret);
      setSecret(''); setConfirmClear(false); setNotice(clear ? 'Credential cleared.' : 'Credential saved securely.');
    } catch (error) { setSaveError(getApiErrorMessage(error, 'Credential update failed. Your draft is preserved.')); }
    finally { credentialLock.current = false; setCredentialPending(false); }
  };
  return (
    <form aria-label="Provider configuration" className="space-y-6" onSubmit={event => { event.preventDefault(); void save(); }} noValidate>
      <div className="flex items-center justify-between gap-3"><h3 className="font-semibold text-hcl-navy">Configuration</h3><span role="status" className="text-xs text-hcl-muted">{dirty ? 'Unsaved changes' : notice || 'Saved configuration'}</span></div>
      {saveError && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800">{saveError}</p>}
      <fieldset disabled={readOnly || busy} className="space-y-6 disabled:opacity-80">
        <Section title="Runtime use" help="Enabling a provider makes it available to component lifecycle refreshes. Verification is a separate operation.">
          <label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={draft.enabled} onChange={e => set('enabled', e.target.checked)} className="h-4 w-4 accent-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" />Enabled</label>
        </Section>
        <Section title="Connection" help={caps?.network ? 'Custom destinations must be approved by platform egress policy.' : 'This provider verifies its configured source locally.'}>
          {caps?.editable_endpoint ? <Field label="Endpoint URL" value={draft.endpoint} error={errors.endpoint} onChange={v => set('endpoint', v)} placeholder={caps.effective_endpoint ?? ''} /> : caps?.effective_endpoint ? <div className="rounded-lg border border-border bg-surface-muted p-3"><span className="text-xs text-hcl-muted">Effective source · read-only</span><p title={caps.effective_endpoint} className="mt-1 break-words text-sm text-hcl-navy">{caps.effective_endpoint}</p></div> : null}
          {caps?.feed_urls && <label className="block text-sm font-medium">Feed URLs<textarea aria-label="Feed URLs" value={draft.feeds} onChange={e => set('feeds', e.target.value)} className={inputClass + ' min-h-28'} aria-invalid={!!errors.feeds} aria-describedby={errors.feeds ? 'feeds-error' : undefined} placeholder="https://approved-host/lifecycle.json" />{errors.feeds && <span id="feeds-error" role="alert" className="mt-1 block text-xs text-red-700">{errors.feeds}</span>}</label>}
          {caps?.config_fields.includes('db_path') && !advanced && <Field label="Database path" value={String(parsed?.db_path ?? '')} onChange={value => set('config', JSON.stringify({ ...(parsed ?? provider.config), db_path: value }, null, 2))} error={errors.config} placeholder="/approved/path/xeol.db" />}
          {!!caps?.config_fields.length && <><Button type="button" variant="ghost" size="sm" onClick={() => { if (advanced && !parsed) { setErrors({ config: 'Configuration must be a valid JSON object. Your draft has been preserved.' }); return; } setAdvanced(!advanced); }}>{advanced ? 'Use guided settings' : 'Advanced configuration'}</Button>{(advanced || !caps.config_fields.includes('db_path')) && <label className="block text-sm font-medium">Configuration JSON<textarea aria-label="Configuration JSON" value={draft.config} onChange={e => set('config', e.target.value)} className={inputClass + ' min-h-32 font-mono text-xs'} aria-invalid={!!errors.config} aria-describedby={errors.config ? 'config-error' : undefined} />{errors.config && <span id="config-error" role="alert" className="mt-1 block text-xs text-red-700">{errors.config}</span>}</label>}</>}
          {!caps?.editable_endpoint && !caps?.feed_urls && !caps?.config_fields.length && !caps?.effective_endpoint && <p className="text-sm text-hcl-muted">No connection settings are required for this source.</p>}
        </Section>
        <Section title="Reliability" help="Lower priority runs first. Authoritative evidence and manual overrides retain their existing precedence.">
          <div className="grid gap-4 sm:grid-cols-2"><Field label="Priority" value={draft.priority} onChange={v => set('priority', v)} type="number" min={1} max={1000} error={errors.priority} />{caps?.network && <><Field label="Timeout (seconds)" value={draft.timeout} onChange={v => set('timeout', v)} type="number" min={1} max={60} error={errors.timeout} /><Field label="Retries" value={draft.retries} onChange={v => set('retries', v)} type="number" min={0} max={10} error={errors.retries} /><label className="flex items-center gap-2 self-center text-sm"><input type="checkbox" checked={draft.breaker} onChange={e => set('breaker', e.target.checked)} className="h-4 w-4 accent-hcl-blue" />Circuit breaker</label></>}</div>
          {caps?.network && <p className="text-xs leading-relaxed text-hcl-muted">Timeout applies per HTTP request. Retries cover eligible transient failures with backoff. The circuit breaker pauses repeated failures; its state is local to each backend process.</p>}
        </Section>
        <Section title="Caching" help="Leave a field empty to use its effective default. Combined results use the shortest TTL of the consulted providers.">
          <div className="grid gap-4 sm:grid-cols-2">{([['known', 'Known results (days)', 'known_days'], ['unknown', 'Unknown results (hours)', 'unknown_hours'], ['failure', 'Failures (minutes)', 'failure_minutes'], ['deprecated', 'Deprecated results (days)', 'deprecated_days']] as const).map(([key, label, defaultKey]) => <Field key={key} label={label} value={draft[key]} onChange={v => set(key, v)} type="number" min={1} error={errors[key]} placeholder={caps?.cache_defaults[defaultKey]?.toString()} help={`Effective default: ${caps?.cache_defaults[defaultKey] ?? 'platform setting'}`} />)}</div>
        </Section>
      </fieldset>
      {caps?.secret_name && <Section title="Authentication" help="Existing values are never returned or displayed. Credential updates are saved separately from configuration.">
        <p className="text-sm text-hcl-navy">{inherited ? credentialConfigured ? 'Credential managed by platform' : 'No platform credential recorded' : credentialConfigured ? 'Credential configured' : 'No credential saved'}</p>
        {inherited && <p className="text-xs text-hcl-muted">Save a tenant override before adding a tenant credential. Platform credentials are not copied.</p>}
        {!readOnly && !inherited && <><label className="block text-sm font-medium">New credential<input aria-label="Provider credential" type="password" autoComplete="new-password" value={secret} onChange={e => { setSecret(e.target.value); setNotice(''); }} className={inputClass} disabled={credentialPending || busy} /></label><div className="flex flex-wrap gap-2"><Button type="button" variant="secondary" size="sm" loading={credentialPending && !confirmClear} disabled={!secret.trim() || credentialPending || busy} onClick={() => void credentialAction()}><KeyRound className="h-3.5 w-3.5" />Save credential</Button>{credentialConfigured && <Button type="button" variant="ghost" size="sm" disabled={credentialPending || busy} onClick={() => setConfirmClear(true)}><Trash2 className="h-3.5 w-3.5" />Clear credential</Button>}</div></>}
        {confirmClear && <div role="alert" className="rounded-lg border border-border p-3 text-sm"><p>Clear this scope’s credential? Requests requiring it may fail until a replacement is saved.</p><div className="mt-3 flex gap-2"><Button type="button" variant="secondary" size="sm" onClick={() => setConfirmClear(false)}>Keep credential</Button><Button type="button" variant="danger" size="sm" loading={credentialPending} onClick={() => void credentialAction(true)}>Confirm clear</Button></div></div>}
      </Section>}
      {!readOnly && <div className="sticky bottom-0 -mx-6 border-t border-border bg-surface px-6 py-4">
        {confirmDisable ? <div role="alert" className="space-y-3"><p className="text-sm text-hcl-navy">Disable this platform provider? Tenants inheriting this setting will stop using it. Tenants with overrides retain their own settings.</p><div className="flex gap-2"><Button type="button" variant="secondary" onClick={() => setConfirmDisable(false)}>Keep editing</Button><Button type="button" variant="danger" onClick={() => void save(true)} loading={busy}>Disable and save</Button></div></div> : <div className="flex items-center justify-between gap-3"><span className="text-xs text-hcl-muted">{dirty ? 'Review and save your changes.' : 'All configuration changes saved.'}</span><Button type="submit" loading={busy} disabled={busy || credentialPending || !dirty}><Save className="h-4 w-4" />{inherited ? 'Save tenant override' : 'Save changes'}</Button></div>}
      </div>}
    </form>
  );
}
function Section({ title, help, children }: { title: string; help: string; children: React.ReactNode }) {
  return <section className="space-y-3"><div><h4 className="text-sm font-semibold text-hcl-navy">{title}</h4><p className="mt-1 text-xs leading-relaxed text-hcl-muted">{help}</p></div>{children}</section>;
}
function Field({ label, value, onChange, type = 'text', min, max, error, placeholder, help }: { label: string; value: string; onChange: (value: string) => void; type?: string; min?: number; max?: number; error?: string; placeholder?: string; help?: string }) {
  const id = label.toLowerCase().replace(/[^a-z0-9]/g, '-');
  return <label className="block text-sm font-medium text-hcl-navy">{label}<input aria-label={label} value={value} onChange={e => onChange(e.target.value)} type={type} min={min} max={max} placeholder={placeholder} className={inputClass} aria-invalid={!!error} aria-describedby={error ? `${id}-error` : help ? `${id}-help` : undefined} />{error && <span id={`${id}-error`} role="alert" className="mt-1 block text-xs text-red-700">{error}</span>}{help && <span id={`${id}-help`} className="mt-1 block text-xs font-normal text-hcl-muted">{help}</span>}</label>;
}
