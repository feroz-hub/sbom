import { describe, expect, it } from 'vitest';
import { verificationMessage, verificationState } from './aiVerification';
import type { AiConnectionErrorKind, AiConnectionTestResult } from '@/types/ai';

describe('modern model verification', () => {
  it.each(['permission', 'unsupported_model', 'unsupported_parameter', 'quota', 'timeout', 'invalid_json', 'incomplete', 'refusal', 'budget_exceeded'] satisfies AiConnectionErrorKind[])(
    'shows a controlled actionable message for %s', (kind) => {
      const result: AiConnectionTestResult = {
        success: false, error_kind: kind, provider: 'openai', model_tested: 'gpt-6-luna',
        error_message: 'arbitrary-provider-secret', latency_ms: 1, detected_models: [],
      };
      expect(verificationMessage(result).text).not.toContain('arbitrary-provider-secret');
      expect(verificationMessage(result).title).toBe('Model verification failed');
      expect(verificationState(result)).not.toBe('INVALID_CREDENTIALS');
    },
  );
});
