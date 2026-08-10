// @vitest-environment jsdom
/**
 * TestResultDisplay — typed-error UI feedback (Phase 3 §3.3).
 *
 * The error_kind enum is the discriminator. Each kind maps to a
 * specific message; this suite verifies every branch.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TestResultDisplay } from '../AddProviderDialog/TestResultDisplay';
import { makeTestResult } from './test-utils';


describe('TestResultDisplay', () => {
  it('shows "Testing…" while in flight', () => {
    render(<TestResultDisplay result={null} testing />);
    expect(screen.getByRole('status')).toHaveTextContent(/Testing/i);
  });

  it('shows "not tested" when there is no result yet', () => {
    render(<TestResultDisplay result={null} testing={false} />);
    expect(screen.getByText(/not tested/i)).toBeInTheDocument();
  });

  it('shows green success message with latency', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({ latency_ms: 412, detected_models: ['m1', 'm2'] })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-success')).toBeInTheDocument();
    expect(screen.getByTestId('test-result-success')).toHaveTextContent('412ms');
    expect(screen.getByTestId('test-result-success')).toHaveTextContent('2 model(s) available');
  });

  it('renders auth-error branch', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({
          success: false,
          error_kind: 'auth',
          error_message: 'Bad key',
          latency_ms: null,
          detected_models: [],
        })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-auth')).toBeInTheDocument();
    expect(screen.getByText(/Invalid API key/i)).toBeInTheDocument();
  });

  it('renders network-error branch', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({
          success: false,
          error_kind: 'network',
          error_message: 'connect timeout',
          latency_ms: null,
          detected_models: [],
        })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-network')).toBeInTheDocument();
    expect(screen.getByText(/Couldn't reach the provider/i)).toBeInTheDocument();
  });

  it('renders rate-limit branch', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({
          success: false,
          error_kind: 'rate_limit',
          error_message: 'too many',
          latency_ms: null,
          detected_models: [],
        })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-rate-limit')).toBeInTheDocument();
  });

  it('renders model-not-found branch with available list', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({
          success: false,
          error_kind: 'model_not_found',
          error_message: 'no such model',
          latency_ms: null,
          model_tested: 'fake-model',
          detected_models: ['gemini-2.5-flash', 'gemini-2.5-pro'],
        })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-model')).toBeInTheDocument();
    expect(screen.getByText(/fake-model isn't available/i)).toBeInTheDocument();
    expect(screen.getByText(/Available:.*gemini-2\.5-flash/)).toBeInTheDocument();
  });

  it('renders unknown branch as the catch-all', () => {
    render(
      <TestResultDisplay
        result={makeTestResult({
          success: false,
          error_kind: 'unknown',
          error_message: 'mystery',
          latency_ms: null,
          detected_models: [],
        })}
        testing={false}
      />,
    );
    expect(screen.getByTestId('test-result-unknown')).toBeInTheDocument();
    expect(screen.getByText(/mystery/)).toBeInTheDocument();
  });
});
