// @vitest-environment jsdom
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Breadcrumb } from './Breadcrumb';

describe('Shared breadcrumb renderer', () => {
  it('renders semantic navigation from page-provided data', () => {
    render(<Breadcrumb items={[{ label: 'Platform', href: '/platform' }, { label: 'Tenants', href: '/settings/platform/tenants' }, { label: 'Wellysis' }]} />);
    const nav = screen.getAllByRole('navigation', { name: 'Breadcrumb' });
    expect(nav).toHaveLength(1);
    expect(within(nav[0]).getAllByRole('listitem')).toHaveLength(3);
    expect(within(nav[0]).getByText('Wellysis')).toHaveAttribute('aria-current', 'page');
    expect(screen.queryByRole('link', { name: 'Wellysis' })).not.toBeInTheDocument();
  });
  it('does not render empty breadcrumb navigation', () => {
    render(<Breadcrumb items={[]} />);
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
  });
  it('retains parent links when a header supplies only ancestor items', () => {
    render(<Breadcrumb items={[{ label: 'SBOMs', href: '/sboms' }]} />);
    expect(screen.getByRole('link', { name: 'SBOMs' })).toHaveAttribute('href', '/sboms');
  });
});
