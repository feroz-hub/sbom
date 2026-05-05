'use client';

import { AlertCircle, CheckCircle, Info, Loader2, ShieldAlert } from 'lucide-react';
import type { AiConnectionTestResult } from '@/types/ai';

interface TestResultDisplayProps {
  result: AiConnectionTestResult | null;
  testing: boolean;
}

/**
 * Phase 3 §3.3 — typed-error-kind UI feedback for the test button.
 *
 * The ``error_kind`` enum is the discriminator: each kind maps to a
 * specific message + icon + colour. Never parse ``error_message`` to
 * decide UX (it's a free-form string for debugging).
 */
export function TestResultDisplay({ result, testing }: TestResultDisplayProps) {
  if (testing) {
    return (
      <p className="flex items-center gap-2 text-sm text-hcl-muted" role="status">
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Testing…
      </p>
    );
  }
  if (!result) {
    return (
      <p className="text-sm text-hcl-muted">Status: not tested</p>
    );
  }

  if (result.success) {
    const detected =
      result.detected_models && result.detected_models.length > 0
        ? `${result.detected_models.length} model(s) available`
        : 'connected';
    return (
      <p
        className="flex items-center gap-2 text-sm text-emerald-700"
        role="status"
        data-testid="test-result-success"
      >
        <CheckCircle className="h-4 w-4" aria-hidden />
        Connected. {detected}. Latency:{' '}
        <span className="font-mono">{result.latency_ms ?? '—'}ms</span>
      </p>
    );
  }

  switch (result.error_kind) {
    case 'auth':
      return (
        <p
          className="flex items-start gap-2 text-sm text-red-700"
          role="alert"
          data-testid="test-result-auth"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Invalid API key.</strong> Verify it's copied correctly and
            has the right permissions.
          </span>
        </p>
      );
    case 'network':
      return (
        <p
          className="flex items-start gap-2 text-sm text-amber-700"
          role="alert"
          data-testid="test-result-network"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Couldn't reach the provider.</strong> Check your network or base URL.
          </span>
        </p>
      );
    case 'rate_limit':
      return (
        <p
          className="flex items-start gap-2 text-sm text-violet-700"
          role="status"
          data-testid="test-result-rate-limit"
        >
          <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Connected, but currently rate-limited.</strong> Try again in a moment.
          </span>
        </p>
      );
    case 'model_not_found':
      return (
        <p
          className="flex items-start gap-2 text-sm text-amber-700"
          role="alert"
          data-testid="test-result-model"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Connected, but {result.model_tested ?? 'this model'} isn't available.</strong>
            {result.detected_models.length > 0
              ? ` Available: ${result.detected_models.slice(0, 5).join(', ')}${result.detected_models.length > 5 ? '…' : ''}`
              : ''}
          </span>
        </p>
      );
    case 'invalid_response':
    case 'unknown':
    default:
      return (
        <p
          className="flex items-start gap-2 text-sm text-red-700"
          role="alert"
          data-testid="test-result-unknown"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Test failed.</strong>{' '}
            {result.error_message ?? 'Unknown error.'}
          </span>
        </p>
      );
  }
}
