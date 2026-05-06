// @vitest-environment jsdom
/**
 * Phase 5 typed-error copy + Generate-button disable rules.
 *
 * Each ``error_code`` maps to a specific user-facing string and a specific
 * disable-state for the Generate button. Locking the mapping in tests
 * keeps copy / state drift visible at review time.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { AiFixSection, aiFixErrorCopy } from '../AiFixSection/AiFixSection';
import { GENERATE_DISABLED_CODES, type AiFindingFixEnvelope, type AiFixError } from '@/types/ai';
import { renderWithProviders } from './test-utils';

const getFindingAiFix = vi.fn();
const regenerateFindingAiFix = vi.fn();

vi.mock('@/lib/api', () => ({
  getFindingAiFix: (
    id: number,
    args: { providerName?: string | null },
    signal?: AbortSignal,
  ) => getFindingAiFix(id, args, signal),
  regenerateFindingAiFix: (
    id: number,
    args: { providerName?: string | null },
    signal?: AbortSignal,
  ) => regenerateFindingAiFix(id, args, signal),
}));

beforeEach(() => {
  getFindingAiFix.mockReset();
  regenerateFindingAiFix.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function makeError(overrides: Partial<AiFixError>): AiFindingFixEnvelope {
  return {
    result: null,
    error: {
      finding_id: 1,
      vuln_id: 'CVE-2024-0001',
      component_name: 'lib',
      component_version: '1.0.0',
      error_code: 'unknown',
      message: 'fallback',
      provider_name: 'gemini',
      model_name: 'gemini-2.5-flash',
      upstream_status_code: null,
      upstream_message: null,
      retry_after_seconds: null,
      retry_after_human: null,
      ...overrides,
    },
  };
}

// ─── Pure-function copy mapping ──────────────────────────────────────────────

describe('aiFixErrorCopy', () => {
  it('quota_exceeded interpolates provider, model, and human retry-after', () => {
    const err = makeError({
      error_code: 'quota_exceeded',
      retry_after_human: 'in 4 hours',
      retry_after_seconds: 14400,
    }).error!;
    expect(aiFixErrorCopy(err)).toBe(
      'Daily quota exhausted for gemini (gemini-2.5-flash). Resets in 4 hours, or switch provider in Settings.',
    );
  });

  it('quota_exceeded omits the reset clause when retry_after_human is missing', () => {
    const err = makeError({
      error_code: 'quota_exceeded',
      retry_after_human: null,
      retry_after_seconds: null,
    }).error!;
    expect(aiFixErrorCopy(err)).toBe(
      'Daily quota exhausted for gemini (gemini-2.5-flash). or switch provider in Settings.',
    );
  });

  it('rate_limited surfaces the seconds value', () => {
    const err = makeError({
      error_code: 'rate_limited',
      retry_after_seconds: 12,
    }).error!;
    expect(aiFixErrorCopy(err)).toBe('Rate limit hit for gemini. Retry in 12s.');
  });

  it('rate_limited falls back to "in a moment" when no retry-after is given', () => {
    const err = makeError({
      error_code: 'rate_limited',
      retry_after_seconds: null,
    }).error!;
    expect(aiFixErrorCopy(err)).toBe('Rate limit hit for gemini. Retry in a moment.');
  });

  it('auth_failed mentions the provider and Settings', () => {
    const err = makeError({ error_code: 'auth_failed' }).error!;
    expect(aiFixErrorCopy(err)).toBe('Invalid API key for gemini. Update in Settings.');
  });

  it('model_not_found names the model', () => {
    const err = makeError({ error_code: 'model_not_found' }).error!;
    expect(aiFixErrorCopy(err)).toBe('Model gemini-2.5-flash not available. Update in Settings.');
  });

  it('network_unreachable names the provider', () => {
    const err = makeError({ error_code: 'network_unreachable' }).error!;
    expect(aiFixErrorCopy(err)).toBe("Couldn't reach gemini. Check network or try again.");
  });

  it('provider_down', () => {
    const err = makeError({ error_code: 'provider_down' }).error!;
    expect(aiFixErrorCopy(err)).toBe('gemini is currently unavailable.');
  });

  it('invalid_request includes the upstream message', () => {
    const err = makeError({
      error_code: 'invalid_request',
      upstream_message: 'Unsupported response_format',
    }).error!;
    expect(aiFixErrorCopy(err)).toBe(
      'Request was rejected by gemini: Unsupported response_format',
    );
  });

  it('unknown surfaces the upstream message', () => {
    const err = makeError({
      error_code: 'unknown',
      upstream_message: 'something happened',
    }).error!;
    expect(aiFixErrorCopy(err)).toBe('Unexpected error: something happened');
  });

  it('falls back to providerLabelFallback when provider_name is missing', () => {
    const err = makeError({ error_code: 'auth_failed', provider_name: null }).error!;
    expect(aiFixErrorCopy(err, 'openai')).toBe('Invalid API key for openai. Update in Settings.');
  });

  it('uses the legacy copy for budget_exceeded', () => {
    const err = makeError({ error_code: 'budget_exceeded' }).error!;
    expect(aiFixErrorCopy(err)).toBe(
      'Daily AI budget reached. Increase the cap in Settings or wait until tomorrow.',
    );
  });

  it('crucially does NOT mention "openai" in the gemini quota copy', () => {
    const err = makeError({
      error_code: 'quota_exceeded',
      provider_name: 'gemini',
      retry_after_human: 'in 35s',
    }).error!;
    expect(aiFixErrorCopy(err).toLowerCase()).not.toContain('openai');
    expect(aiFixErrorCopy(err)).toContain('gemini');
  });
});

// ─── Generate-button disable behavior ────────────────────────────────────────

describe('AiFixSection — Generate button disable rules', () => {
  for (const code of GENERATE_DISABLED_CODES) {
    it(`disables the Generate button for ${code}`, async () => {
      getFindingAiFix.mockResolvedValue(
        makeError({ error_code: code, retry_after_human: 'in 4 hours' }),
      );
      renderWithProviders(<AiFixSection findingId={1} providerLabel="gemini" />);
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /generate ai remediation/i })).toBeInTheDocument();
      });
      const btn = screen.getByRole('button', { name: /generate ai remediation/i });
      expect(btn).toBeDisabled();
    });
  }

  it('does NOT disable the Generate button for rate_limited (clicking is the right move)', async () => {
    getFindingAiFix.mockResolvedValue(
      makeError({ error_code: 'rate_limited', retry_after_seconds: 5 }),
    );
    renderWithProviders(<AiFixSection findingId={1} providerLabel="gemini" />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /generate ai remediation/i })).toBeInTheDocument();
    });
    const btn = screen.getByRole('button', { name: /generate ai remediation/i });
    expect(btn).not.toBeDisabled();
  });

  it('does NOT disable the Generate button for schema_parse_failed (regenerating may succeed)', async () => {
    getFindingAiFix.mockResolvedValue(makeError({ error_code: 'schema_parse_failed' }));
    renderWithProviders(<AiFixSection findingId={1} providerLabel="gemini" />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /generate ai remediation/i })).toBeInTheDocument();
    });
    const btn = screen.getByRole('button', { name: /generate ai remediation/i });
    expect(btn).not.toBeDisabled();
  });

  it('renders the typed quota copy verbatim in the modal', async () => {
    getFindingAiFix.mockResolvedValue(
      makeError({
        error_code: 'quota_exceeded',
        retry_after_human: 'in 4 hours',
        retry_after_seconds: 14400,
      }),
    );
    renderWithProviders(<AiFixSection findingId={1} providerLabel="gemini" />);
    await waitFor(() => {
      expect(
        screen.getByText(
          'Daily quota exhausted for gemini (gemini-2.5-flash). Resets in 4 hours, or switch provider in Settings.',
        ),
      ).toBeInTheDocument();
    });
  });
});
