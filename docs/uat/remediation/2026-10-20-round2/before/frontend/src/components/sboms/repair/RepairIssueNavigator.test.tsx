// @vitest-environment jsdom
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { RepairIssueNavigator } from './RepairIssueNavigator';
import { presentIssues } from '@/lib/repairIssuePresentation';
import type { ValidationErrorEntry } from '@/types';
const orphan: ValidationErrorEntry = { code: 'SBOM_VAL_I075_ORPHAN_COMPONENT', severity: 'info', stage: 'integrity', path: 'components[3]', message: 'Original orphan component details', remediation: null, spec_reference: null };
function setup(entries = [orphan], overrides = {}) {
  const issues = presentIssues(entries); const onNavigate = vi.fn(); const onViewReport = vi.fn();
  render(<RepairIssueNavigator issues={issues} selectedKey={issues[0]?.key ?? null} onSelect={vi.fn()} onNavigate={onNavigate} canNavigate={() => true} passed errorCount={0} warningCount={0} busy={false} importReady importHint="Ready" onViewReport={onViewReport} {...overrides} />);
  return { onNavigate, onViewReport };
}
describe('compact validation issue navigator', () => {
  it('shows passed with info without a large success card or severity relabeling', () => {
    const { onNavigate } = setup();
    expect(screen.getByText('Passed')).toBeInTheDocument();
    expect(screen.queryByText('SBOM validation passed')).not.toBeInTheDocument();
    expect(screen.getByRole('article', { name: 'I075 Orphan component' })).toBeInTheDocument();
    expect(screen.getByText('INFO')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Info 1' })).toBeInTheDocument();
    expect(screen.getByText('✓ No blocking errors')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Go to location →' }));
    expect(onNavigate).toHaveBeenCalledWith(expect.objectContaining({ entry: orphan }));
    expect(screen.getByText(orphan.message)).not.toBeVisible();
  });
  it('filters warnings in a passed session and searches original codes', () => {
    setup([{ ...orphan, severity: 'warning' }], { warningCount: 1 });
    fireEvent.click(screen.getByRole('button', { name: 'Errors 0' }));
    expect(screen.getByText('No issues match this filter.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Warnings 1' }));
    fireEvent.change(screen.getByLabelText('Search validation issues'), { target: { value: 'ORPHAN_COMPONENT' } });
    expect(screen.getByRole('article')).toBeInTheDocument();
    expect(screen.getByText('0 errors · 1 warning')).toBeInTheDocument();
  });
  it('uses parent import gating for a passed but unsaved draft', () => {
    setup([orphan], { importReady: false, importHint: 'Revalidate the changed draft.' });
    expect(screen.getByText('Revalidate the changed draft.')).toBeInTheDocument();
    expect(screen.queryByText(/This SBOM can be imported/)).not.toBeInTheDocument();
  });
  it('shows failed blocking errors and only one selected issue', () => {
    setup([{ ...orphan, severity: 'error' }, { ...orphan, path: 'components[4]', severity: 'error' }], { passed: false, errorCount: 2, importReady: false, importHint: 'Resolve and revalidate.' });
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.getByText('✕ 2 blocking errors remain')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Issue list')).getAllByRole('button', { pressed: true })).toHaveLength(1);
  });
  it('offers report viewing in the compact clean state', () => {
    const { onViewReport } = setup([]);
    fireEvent.click(screen.getByRole('button', { name: 'View validation report' }));
    expect(onViewReport).toHaveBeenCalledOnce();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });
});


it('expands complete finding information without line clamping or identifier overflow', () => {
  const path = 'components[3].' + 'veryLongProperty'.repeat(80);
  const guidance = 'Review the declared relationship. '.repeat(80);
  setup([{ ...orphan, path, remediation: guidance }], { currentValue: 'pkg:generic/' + 'long'.repeat(100) });
  const article = screen.getByRole('article');
  const details = within(article).getByText('Details').closest('details')!;
  fireEvent.click(within(article).getByText('Details'));
  expect(details.open).toBe(true);
  expect(within(details).getByText(guidance.trim())).toBeVisible();
  expect(within(details).getAllByText(path)[0]).toBeVisible();
  expect(within(details).getByText('Current value')).toBeVisible();
  expect(article.querySelector('[class*="line-clamp"]')).toBeNull();
  expect(screen.getByLabelText('Issue list')).toHaveClass('overflow-y-auto', 'overflow-x-hidden', 'min-h-0');
  expect(screen.getByRole('heading', { name: 'Validation Issues' })).toBeVisible();
  expect(screen.getByText('✓ No blocking errors')).toBeVisible();
});
it('allows mobile Escape to hide issues', () => {
  const onHide = vi.fn();
  const previous = window.matchMedia;
  window.matchMedia = vi.fn().mockReturnValue({ matches: true });
  try {
    setup([orphan], { onHide });
    fireEvent.keyDown(screen.getByLabelText('Search validation issues'), { key: 'Escape' });
    expect(onHide).toHaveBeenCalledOnce();
  } finally { window.matchMedia = previous; }
});

vi.mock('@/hooks/useAuth', async () => ({ useAuth: (await import('@/test/authorizedAuth')).authorizedAuth }));
