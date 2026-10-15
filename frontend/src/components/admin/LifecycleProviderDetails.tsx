'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, CircleHelp, GitBranch, RefreshCw, ShieldCheck } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { formatDate } from '@/lib/utils';
import { hasVerificationProof, isStaticReference, isUnsupported, providerStatus, providerSubtitle } from '@/lib/lifecycle-provider-presentation';
import type { LifecycleProviderConfig, LifecycleProviderTestResult, LifecycleProviderUpdatePayload } from '@/types';
import { LifecycleProviderForm } from './LifecycleProviderForm';

type Section = 'Overview' | 'Configuration' | 'Verification' | 'Activity';
interface Props {
  provider: LifecycleProviderConfig;
  result?: LifecycleProviderTestResult | null;
  verificationError?: string | null;
  scope: 'platform' | 'tenant'; tenantName: string;
  canUpdate: boolean; canTest: boolean; canSync: boolean;
  saving: boolean; verifying: boolean; reloading: boolean; resetting: boolean;
  onClose: () => void;
  onVerify: () => void; onReload: () => void; onReset: () => Promise<unknown>;
  onSave: (key: string, value: LifecycleProviderUpdatePayload) => Promise<void>;
  onSaveSecret: (key: string, name: string, value: string) => Promise<void>;
  onDeleteSecret: (key: string, name: string) => Promise<void>;
}
export function ProviderStatus({ provider, result }: { provider: LifecycleProviderConfig; result?: LifecycleProviderTestResult | null }) {
  const status = providerStatus(provider, result);
  return <span title={status.help}><Badge variant={status.tone}>{status.label}</Badge></span>;
}
export const recorded = (value?: string | null) => value && Number.isFinite(Date.parse(value)) ? formatDate(value) : 'Not yet recorded';

export function LifecycleProviderDetails({ provider, result, verificationError, scope, tenantName, canUpdate, canTest, canSync, saving, verifying, reloading, resetting, onClose, onVerify, onReload, onReset, onSave, onSaveSecret, onDeleteSecret }: Props) {
  const [section, setSection] = useState<Section>('Overview');
  const [customizing, setCustomizing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [confirm, setConfirm] = useState<'discard' | 'reset' | null>(null);
  const [actionError, setActionError] = useState('');
  const caps = provider.capabilities;
  const unsupported = isUnsupported(provider);
  const inherited = scope === 'tenant' && !provider.override_enabled;
  const probe = result ?? provider.last_probe;
  const busy = saving || verifying || reloading || resetting;
  const source = (caps?.feed_urls ? provider.feed_urls.join('\n') : caps?.config_fields.includes('db_path') ? String(provider.config.db_path ?? '') : caps?.editable_endpoint ? provider.base_url || caps.effective_endpoint : caps?.effective_endpoint) || 'Not configured';
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    return () => { if (opener?.isConnected) opener.focus(); };
  }, []);
  const close = () => { if (busy) return; if (confirm) { setConfirm(null); return; } if (dirty) setConfirm('discard'); else onClose(); };
  const reset = async () => {
    try { await onReset(); setConfirm(null); setCustomizing(false); setDirty(false); }
    catch { setActionError('The override could not be reset. Your current configuration is retained.'); }
  };
  const canVerify = canTest && provider.enabled && !unsupported && !dirty && !busy;
  return <Dialog open onClose={close} title={provider.display_name} placement="right" dismissOnBackdrop={!busy}>
    {confirm && <section role="alert" aria-label={confirm === 'discard' ? 'Unsaved changes' : 'Reset tenant override'} className="space-y-4 p-6">
      <h3 className="text-base font-semibold text-hcl-navy">{confirm === 'discard' ? 'Discard unsaved changes?' : 'Return to platform defaults?'}</h3>
      <p className="text-sm leading-relaxed text-hcl-muted">{confirm === 'discard' ? 'Your unsaved configuration and credential drafts will be discarded. Saved settings will be retained.' : `This removes ${tenantName}’s provider override and tenant credential. The provider will inherit the platform configuration. Any unsaved drafts will be discarded.`}</p>
      {actionError && <p role="alert" className="text-sm text-red-700">{actionError}</p>}
      <div className="flex flex-wrap gap-2"><Button autoFocus variant="secondary" onClick={() => setConfirm(null)} disabled={resetting}>Keep editing</Button><Button variant="danger" loading={resetting} onClick={() => confirm === 'discard' ? onClose() : void reset()}>{confirm === 'discard' ? 'Discard changes' : 'Reset to platform defaults'}</Button></div>
    </section>}
    <div hidden={!!confirm}>
      <div className="space-y-3 border-b border-border px-6 py-4">
        <div className="flex flex-wrap items-center gap-2"><ProviderStatus provider={provider} result={probe} /><Badge variant="gray">{provider.enabled ? 'Enabled' : 'Disabled'}</Badge>{inherited && <Badge variant="gray">Inherited</Badge>}</div>
        <p className="text-sm leading-relaxed text-hcl-muted">{providerSubtitle(provider)}</p>
      </div>
      <nav aria-label="Provider sections" className="sticky top-0 z-10 grid grid-cols-4 border-b border-border bg-surface px-3">
        {(['Overview', 'Configuration', 'Verification', 'Activity'] as const).map(item => <button key={item} type="button" aria-pressed={section === item} disabled={item === 'Configuration' && unsupported} onClick={() => setSection(item)} className={`min-w-0 border-b-2 px-1 py-3 text-xs font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-hcl-blue motion-reduce:transition-none disabled:cursor-not-allowed disabled:opacity-40 sm:text-sm ${section === item ? 'border-hcl-blue text-hcl-blue' : 'border-transparent text-hcl-muted hover:text-hcl-navy'}`}>{item}</button>)}
      </nav>
      <div className="px-6 py-5">
        <section hidden={section !== 'Overview'} className="space-y-5" aria-label="Provider overview">
          <div><h3 className="text-sm font-semibold text-hcl-navy">Source and coverage</h3><p className="mt-2 text-sm leading-relaxed text-hcl-muted">{caps?.coverage ?? 'Coverage information has not been supplied by this provider.'}</p></div>
          {unsupported && <Callout>Not implemented — no live vendor integration. This provider cannot be activated or verified.</Callout>}
          {isStaticReference(provider) && <Callout>Static RHEL reference — freshness not verified. A successful local check does not establish a live vendor connection.</Callout>}
          <dl className="divide-y divide-border rounded-lg border border-border px-4">
            <Detail label="Source type">{caps?.data_source_type ?? provider.provider_type}</Detail>
            <Detail label="Effective source"><span title={source} className="block whitespace-pre-wrap break-all">{source}</span></Detail>
            <Detail label="Configuration">{provider.configuration_status === 'missing_source' ? 'Source required' : provider.configuration_status === 'invalid' ? 'Review configuration' : unsupported ? 'Not implemented' : 'Saved configuration'}</Detail>
            <Detail label="Ownership">{scope === 'platform' ? 'Platform defaults' : inherited ? `Inherited from platform · ${tenantName}` : `Tenant override · ${tenantName}`}</Detail>
            <Detail label="Priority">{provider.priority} <span className="text-hcl-muted">· lower runs first</span></Detail>
            <Detail label="Credential">{caps?.secret_name ? provider.has_secret ? inherited ? 'Managed by platform' : 'Configured · value hidden' : 'Not recorded' : 'Not required / not supported'}</Detail>
          </dl>
          {inherited && <Callout><GitBranch className="mr-1 inline h-4 w-4" />Platform changes apply until you save a tenant override. Tenant credentials are never copied from platform storage.</Callout>}
          <div className="flex flex-wrap gap-2">{!unsupported && <Button variant="secondary" onClick={() => setSection('Configuration')}>{canUpdate ? 'Configure provider' : 'View configuration'}</Button>}<Button variant="ghost" onClick={() => setSection('Verification')}><ShieldCheck className="h-4 w-4" />View verification</Button></div>
        </section>
        <section hidden={section !== 'Configuration'} className="space-y-5" aria-label="Configuration settings">
          {inherited && <Callout><p>You are viewing the platform configuration for {tenantName}.</p>{canUpdate && !customizing && <Button className="mt-3" variant="secondary" size="sm" onClick={() => setCustomizing(true)}>Customize for {tenantName}</Button>}{customizing && <p className="mt-2">Your override will be created when you save. Save it before adding a tenant credential.</p>}</Callout>}
          {!canUpdate && <Callout>You have read-only access to this configuration.</Callout>}
          <LifecycleProviderForm key={`${provider.provider_key}:${provider.override_enabled ? 'override' : 'inherited'}`} provider={provider} inherited={inherited} scope={scope} readOnly={!canUpdate || unsupported || (inherited && !customizing)} credentialConfigured={provider.has_secret} onDirtyChange={setDirty} onClose={close} onSave={onSave} onSaveSecret={onSaveSecret} onDeleteSecret={onDeleteSecret} saving={busy} />
          {scope === 'tenant' && provider.override_enabled && canUpdate && <div className="border-t border-border pt-4"><p className="mb-2 text-xs text-hcl-muted">Restore inheritance for this provider and remove its tenant credential.</p><Button variant="ghost" size="sm" disabled={busy} onClick={() => setConfirm('reset')}>Reset to platform defaults</Button></div>}
        </section>
        <section hidden={section !== 'Verification'} className="space-y-5" aria-label="Provider verification">
          <div><h3 className="text-sm font-semibold text-hcl-navy">{caps?.network ? 'Verify the connection' : 'Verify the source'}</h3><p className="mt-2 text-sm leading-relaxed text-hcl-muted">A successful verification confirms the operation shown below. Component matching and lifecycle evidence are separate coverage checks.</p></div>
          {unsupported ? <Callout>Not implemented — no live vendor integration.</Callout> : <>
            {!provider.enabled && <Callout>The current API skips disabled providers. Enable and save the provider before verification; verification itself does not enable runtime use.</Callout>}
            {dirty && <Callout>Save or discard your draft before verifying. Verification uses saved settings.</Callout>}
            {inherited && <p className="text-xs text-hcl-muted">Verification uses the inherited configuration and effective platform credentials. Its result is shown in this session; platform verification records are not changed.</p>}
            <Button onClick={onVerify} loading={verifying} disabled={!canVerify}><ShieldCheck className="h-4 w-4" />{caps?.network ? 'Verify connection' : 'Verify source'}</Button>
          </>}
          {verificationError && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800">{verificationError} No new verification result was recorded.</p>}
          <div role="status" aria-live="polite" aria-atomic="true">{verifying ? <p className="text-sm text-hcl-muted">Verification in progress… Waiting for the provider response.</p> : probe ? <VerificationResult result={probe} provider={provider} /> : <Callout>Not verified yet. Run verification to record what this provider can actually return.</Callout>}</div>
          {canSync && caps?.sync_action && <div className="border-t border-border pt-4"><h4 className="text-sm font-semibold text-hcl-navy">Local source cache</h4><p className="my-2 text-xs leading-relaxed text-hcl-muted">Reload the source cache in the receiving backend process. This is an inline operation and does not queue a synchronization job.</p><Button variant="secondary" onClick={onReload} loading={reloading} disabled={busy || dirty}><RefreshCw className="h-4 w-4" />Reload cache</Button></div>}
        </section>
        <section hidden={section !== 'Activity'} className="space-y-4" aria-label="Provider activity"><h3 className="text-sm font-semibold text-hcl-navy">Last recorded activity</h3><p className="text-xs text-hcl-muted">The service exposes last-known events, not a complete activity history.</p><dl className="divide-y divide-border rounded-lg border border-border px-4">
          <Detail label="Successful verification">{recorded(hasVerificationProof(provider) ? provider.last_probe?.checked_at : null)}</Detail>
          <Detail label="Verification attempt">{recorded(provider.last_probe?.checked_at)}</Detail>
          <Detail label="Actual lifecycle lookup">{recorded(provider.last_lookup_at)}</Detail>
          <Detail label="Last failure">{recorded(provider.last_failure_at)}</Detail>
          <Detail label="Failure details">{provider.last_failure_message || 'Not yet recorded'}</Detail>
          <Detail label="Configuration updated">{recorded(provider.updated_at)}</Detail>
          <Detail label="Circuit breaker">{!provider.circuit_breaker_enabled ? 'Disabled' : provider.runtime_status?.circuit_open == null ? 'Not yet recorded' : provider.runtime_status.circuit_open ? 'Open · requests paused' : 'Closed'}<p className="mt-1 text-xs text-hcl-muted">Runtime state reflects the responding backend process.</p></Detail>
        </dl><details className="rounded-lg border border-border p-3 text-xs"><summary className="cursor-pointer font-medium">Technical identifier</summary><p className="mt-2 break-all font-mono text-hcl-muted">{provider.provider_key}</p></details></section>
      </div>
    </div>
  </Dialog>;
}
function Callout({ children }: { children: React.ReactNode }) { return <div className="rounded-lg border border-border bg-surface-muted p-3 text-sm leading-relaxed text-hcl-muted">{children}</div>; }
function Detail({ label, children }: { label: string; children: React.ReactNode }) { return <div className="grid gap-1 py-3 text-sm sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4"><dt className="text-hcl-muted">{label}</dt><dd className="min-w-0 break-words text-hcl-navy">{children}</dd></div>; }
function VerificationResult({ result, provider }: { result: LifecycleProviderTestResult; provider: LifecycleProviderConfig }) {
  const check = (value?: boolean | null, empty = 'Not verified / not applicable') => value == null ? empty : value ? 'Confirmed' : 'Not confirmed';
  const nextAction = !result.success ? result.status === 'disabled' ? 'Enable and save the provider before verification.' : result.authentication_verified === false ? 'Review the saved credential and its permissions, then verify again.' : 'Review connection settings and the sanitized error below, then retry.' : !hasVerificationProof(provider, result) ? 'Stored verification evidence is incomplete. Run verification to check the source again.' : result.lifecycle_evidence_found ? 'Refresh an authorized SBOM to evaluate its components with the configured provider chain.' : 'The provider is operational for this sample. Review coverage or use another source for lifecycle evidence.';
  return <div className="space-y-4"><div className="flex flex-wrap items-center justify-between gap-2"><ProviderStatus provider={provider} result={result} /><span className="text-xs text-hcl-muted">{result.latency_ms} ms · {recorded(result.checked_at)}</span></div><p className="text-sm text-hcl-navy">{result.message}</p><dl className="divide-y divide-border rounded-lg border border-border px-4">
    <Detail label="Operation">{result.probe_type === 'network' ? 'Network provider request' : result.probe_type === 'local_verification' ? 'Local source verification' : result.probe_type === 'unsupported' ? 'Unsupported operation' : 'Not yet recorded'}</Detail>
    <Detail label="Request attempted">{result.probe_type === 'local_verification' ? 'No network request · local verification' : check(result.real_provider_call)}</Detail><Detail label="Connectivity">{result.probe_type === 'local_verification' ? 'Not applicable · local source' : check(result.connection_verified, 'Not yet recorded')}</Detail><Detail label="Authentication">{check(result.authentication_verified, provider.capabilities?.secret_name ? 'Not yet recorded / not applicable' : 'Not required')}</Detail><Detail label="Response parsing">{check(result.response_valid)}</Detail><Detail label="Sample match">{check(result.sample_matched)}</Detail><Detail label="Lifecycle evidence">{result.lifecycle_evidence_found == null ? 'Not yet recorded' : result.lifecycle_evidence_found ? <span className="inline-flex items-center gap-1"><CheckCircle2 className="h-4 w-4 text-emerald-700" />Evidence found for this sample</span> : 'Not found for this sample'}</Detail>
    {result.http_status != null && <Detail label="HTTP result">{result.http_status}</Detail>}
    {result.sample_component && <Detail label="Sample component">{Object.values(result.sample_component).map(String).join(' · ')}</Detail>}
    {result.error_code && <Detail label="Error code"><span className="break-all font-mono text-xs">{result.error_code}</span></Detail>}
  </dl><Callout><CircleHelp className="mr-1 inline h-4 w-4" />{nextAction}</Callout>{result.sample_result?.sample_evidence != null && <details className="rounded-lg border border-border p-3 text-xs"><summary className="cursor-pointer font-medium">Sample evidence</summary><pre className="mt-2 max-w-full whitespace-pre-wrap break-all text-hcl-muted">{JSON.stringify(result.sample_result.sample_evidence, null, 2)}</pre></details>}</div>;
}
