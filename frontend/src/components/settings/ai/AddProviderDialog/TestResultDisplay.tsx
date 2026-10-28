'use client';
import { AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { verificationMessage } from '@/lib/aiVerification';
import type { AiConnectionTestResult } from '@/types/ai';

export function TestResultDisplay({ result, testing, error }: { result: AiConnectionTestResult | null; testing: boolean; error?: unknown }) {
  if (testing) return <p role="status" className="flex items-center gap-2 text-sm text-hcl-muted"><Loader2 className="h-4 w-4 animate-spin" aria-hidden />Testing…</p>;
  if (!result && !error) return <p className="text-sm text-hcl-muted">Status: not tested. Verification is optional; credentials are saved securely.</p>;
  const message = verificationMessage(result, error);
  const success = message.state === 'VERIFIED';
  const invalid = ['INVALID_CREDENTIALS', 'INVALID_CONFIGURATION'].includes(message.state);
  const kind = error ? 'request-error' : success ? 'success' : ({ auth: 'auth', network: 'network', rate_limit: 'rate-limit', model_not_found: 'model', provider_unavailable: 'transient' } as Record<string, string>)[result?.error_kind ?? ''] ?? 'unknown';
  const Icon = success ? CheckCircle : AlertCircle;
  return <div role={invalid ? 'alert' : 'status'} data-testid={`test-result-${kind}`} className={`rounded-lg border p-3 text-sm ${success ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : invalid ? 'border-red-200 bg-red-50 text-red-800' : 'border-amber-200 bg-amber-50 text-amber-900'}`}><div className="flex gap-2"><Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /><div><strong>{message.title}</strong><p className="mt-1 leading-6">{message.text}</p>{success && <p className="mt-1 text-xs">{result?.detected_models.length ?? 0} model(s) available · Latency: {result?.latency_ms ?? '—'}ms</p>}{result?.http_status && <details className="mt-2 text-xs"><summary className="cursor-pointer">Technical details</summary><p className="mt-1">HTTP {result.http_status}</p></details>}</div></div></div>;
}
