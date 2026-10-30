// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import catalogue from '@/test/permissionCatalogue.json';
import { AiFixGenerateButton } from '../AiFixSection/AiFixGenerateButton';
import { AiFixMetadata } from '../AiFixSection/AiFixMetadata';
import { BatchControls } from '../RunBatchProgress/BatchControls';
import { FreeTierWarningDialog } from '../FreeTierWarningDialog';
import { makeBatchProgress, SAMPLE_FIX_RESULT } from './test-utils';

const state = vi.hoisted(() => ({ permissions: ['analysis:run'], loading: false }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  user: { userId: 'test-user', permissions: state.permissions },
  isLoading: state.loading, isTenantContextLoading: false, bootstrapState: 'ready',
  hasPermission: (permission: string) => state.permissions.includes(permission),
}) }));
beforeEach(() => { state.permissions = ['analysis:run']; state.loading = false; });
const callbacks = () => ({ onTrigger: vi.fn(), onCancel: vi.fn() });

describe('remediation execution controls', () => {
  it.each(Object.entries(catalogue.roles))('matches backend analysis:run grants for %s', (_role, grants) => {
    state.permissions = grants;
    const actions = callbacks();
    render(<><AiFixGenerateButton onGenerate={actions.onTrigger} />
      <BatchControls progress={makeBatchProgress({ status: 'pending', total: 0 })} {...actions} />
      <AiFixMetadata metadata={SAMPLE_FIX_RESULT.metadata} onRegenerate={actions.onTrigger} />
    </>);
    for (const button of screen.getAllByRole('button')) {
      expect(button).toHaveProperty('disabled', !grants.includes('analysis:run'));
    }
  });
  it('allows analysts without settings access and uses unambiguous primary styles', async () => {
    const onGenerate = vi.fn();
    render(<AiFixGenerateButton onGenerate={onGenerate} />);
    const button = screen.getByRole('button');
    expect(button).toBeEnabled();
    expect(button).toHaveClass('bg-[var(--btn-primary)]', 'text-white');
    expect(button).not.toHaveClass('bg-transparent', 'text-hcl-navy');
    await userEvent.click(button);
    expect(onGenerate).toHaveBeenCalledOnce();
  });
  it('explains denied access on focus and blocks mouse and keyboard execution', async () => {
    state.permissions = ['tenant:settings:update'];
    const onGenerate = vi.fn();
    render(<AiFixGenerateButton onGenerate={onGenerate} />);
    const button = screen.getByRole('button');
    expect(button).toBeDisabled(); expect(button).toHaveAttribute('aria-disabled', 'true');
    fireEvent.click(button); await userEvent.tab(); await userEvent.keyboard('{Enter} ');
    expect(button.parentElement).toHaveAccessibleDescription(/permission to run vulnerability analysis/i);
    expect(onGenerate).not.toHaveBeenCalled();
  });
  it('fails closed while permissions load and recovers after tenant context resolves', () => {
    state.loading = true;
    const { rerender } = render(<AiFixGenerateButton onGenerate={vi.fn()} />);
    expect(screen.getByRole('button').parentElement).toHaveAccessibleDescription('Checking your permissions…');
    state.loading = false; rerender(<AiFixGenerateButton onGenerate={vi.fn()} />);
    expect(screen.getByRole('button')).toBeEnabled();
  });
  it('offers Cancel for a durable queued batch', async () => {
    const actions = callbacks();
    render(<BatchControls progress={makeBatchProgress({ status: 'queued' })} {...actions} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(actions.onCancel).toHaveBeenCalledOnce(); expect(actions.onTrigger).not.toHaveBeenCalled();
  });
  it('allows retry after a zero-count failure and explains scope restrictions', () => {
    const props = { progress: makeBatchProgress({ status: 'failed', total: 0 }), ...callbacks() };
    const { rerender } = render(<BatchControls {...props} />);
    expect(screen.getByRole('button')).toBeEnabled();
    rerender(<BatchControls {...props} disabledReason="No AI provider configured." />);
    expect(screen.getByRole('button')).toBeDisabled();
    expect(screen.getByRole('status')).toHaveTextContent('No AI provider configured.');
  });
  it('uses analysis:run for the free-tier confirmation', () => {
    render(<FreeTierWarningDialog open onContinue={vi.fn()} onCancel={vi.fn()} estimate={{
      run_id: '00000000-0000-4000-8000-000000000001', is_local: false, concurrency: 1,
      provider: 'gemini', tier: 'free', findings_to_generate: 75, findings_total: 75,
      cached_count: 0, requests_per_minute: 10, estimated_seconds: 450,
      estimated_cost_usd: 0, bottleneck: 'rate_limit', warning_recommended: true,
    }} />);
    const button = screen.getByRole('button', { name: 'Continue with gemini' });
    expect(button).toBeEnabled(); expect(button).toHaveClass('bg-[var(--btn-primary)]');
  });
});
