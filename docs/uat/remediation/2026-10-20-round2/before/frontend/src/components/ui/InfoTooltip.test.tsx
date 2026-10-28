// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { InfoTooltip } from './InfoTooltip';

afterEach(() => vi.restoreAllMocks());

it.each([
  [20, 48],
  [700, 572],
])('keeps help within a narrow viewport for an anchor at y=%s', (top, expectedTop) => {
  vi.spyOn(window, 'innerWidth', 'get').mockReturnValue(320);
  vi.spyOn(window, 'innerHeight', 'get').mockReturnValue(720);
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    return this.getAttribute('role') === 'tooltip'
      ? { width: 288, height: 120 } as DOMRect
      : { left: 300, top, bottom: top + 20 } as DOMRect;
  });
  render(<div className="overflow-hidden"><InfoTooltip label="Metric" description="Metric explanation" /></div>);
  fireEvent.mouseEnter(screen.getByRole('button'));
  expect(screen.getByRole('tooltip')).toHaveStyle({ left: '24px', top: `${expectedTop}px` });
  expect(screen.getByRole('tooltip').parentElement).toBe(document.body);
});

it('supports keyboard navigation and dismisses pinned help when focus moves', async () => {
  const user = userEvent.setup();
  render(<><InfoTooltip label="Metric" description="Metric explanation" /><button>Next</button></>);
  await user.tab();
  expect(screen.getByRole('button', { name: 'About Metric' })).toHaveFocus();
  expect(screen.getByRole('tooltip')).toHaveTextContent('Metric explanation');
  await user.keyboard('{Enter}');
  await user.tab();
  expect(screen.getByRole('button', { name: 'Next' })).toHaveFocus();
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
});

it('lets the pointer move into the tooltip before dismissing on leave', async () => {
  render(<InfoTooltip label="Metric" description="Metric explanation" />);
  const trigger = screen.getByRole('button');
  fireEvent.mouseEnter(trigger);
  const help = screen.getByRole('tooltip');
  fireEvent.mouseLeave(trigger);
  fireEvent.mouseEnter(help);
  expect(help).toBeInTheDocument();
  fireEvent.mouseLeave(help);
  await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
});
