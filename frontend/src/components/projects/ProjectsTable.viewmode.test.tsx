// @vitest-environment jsdom

/**
 * List/grid toggle on the Projects screen.
 *
 * The risk with a second view is that it quietly becomes a second source of
 * truth — different filtering, a different page slice, or a smaller set of
 * actions. These tests pin the opposite: both views render the same paginated,
 * filtered rows and offer the same operations, and the choice is remembered.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { ProjectsTable } from './ProjectsTable';
import type { Project } from '@/types';

vi.mock('@/lib/api', () => ({
  deleteProject: vi.fn(),
  getProjectDeleteImpact: vi.fn().mockResolvedValue({ can_delete: true, warnings: [], dependent_counts: {} }),
}));

vi.mock('./ProjectModal', () => ({ ProjectModal: () => null }));
vi.mock('@/components/schedules/ProjectScheduleDialog', () => ({ ProjectScheduleDialog: () => null }));

function project(id: number, name: string, status = 1): Project {
  return {
    id,
    project_name: name,
    project_details: `Details for ${name}`,
    project_status: status,
    created_by: 'alice@example.com',
    created_on: '2026-09-01T10:00:00Z',
  } as Project;
}

const PROJECTS = [
  project(3, 'Hospital Software Security'),
  project(2, 'Infusion Pump Cyber security'),
  project(1, 'Retired Programme', 0),
];

function wrap(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{node}</ToastProvider>
    </QueryClientProvider>
  );
}

const toggle = (name: 'List' | 'Grid') => screen.getByRole('radio', { name });

beforeEach(() => {
  window.localStorage.clear();
});

describe('ProjectsTable list/grid toggle', () => {
  it('starts in list view with the table rendered', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    expect(toggle('List')).toHaveAttribute('aria-checked', 'true');
    expect(toggle('Grid')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByRole('region', { name: /projects table/i })).toBeInTheDocument();
  });

  it('replaces the table with cards in grid view, keeping every project', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    fireEvent.click(toggle('Grid'));

    expect(screen.queryByRole('region', { name: /projects table/i })).not.toBeInTheDocument();
    for (const p of PROJECTS) {
      expect(screen.getByText(p.project_name)).toBeInTheDocument();
    }
  });

  it('offers the same actions per project in both views', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    const listActions = screen.getAllByRole('button', { name: /^Edit / }).length;
    fireEvent.click(toggle('Grid'));
    const gridActions = screen.getAllByRole('button', { name: /^Edit / }).length;

    expect(gridActions).toBe(listActions);
    expect(gridActions).toBe(PROJECTS.length);
    // Schedule and Delete travel with Edit.
    expect(screen.getAllByRole('button', { name: /^Delete / })).toHaveLength(PROJECTS.length);
    expect(screen.getAllByRole('button', { name: /^Configure periodic analysis schedule/ })).toHaveLength(
      PROJECTS.length,
    );
  });

  it('applies the search filter to the grid, not just the table', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    fireEvent.click(toggle('Grid'));
    fireEvent.change(screen.getByLabelText(/search/i), { target: { value: 'Infusion' } });

    expect(screen.getByText('Infusion Pump Cyber security')).toBeInTheDocument();
    expect(screen.queryByText('Hospital Software Security')).not.toBeInTheDocument();
  });

  it('shows the filtered-empty message in grid view rather than a blank panel', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    fireEvent.click(toggle('Grid'));
    fireEvent.change(screen.getByLabelText(/search/i), { target: { value: 'zzzz-no-match' } });

    expect(screen.getByText(/No projects match your filters/i)).toBeInTheDocument();
  });

  it('remembers the choice across remounts', () => {
    const first = render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));
    fireEvent.click(toggle('Grid'));
    expect(window.localStorage.getItem('sbom.viewmode.projects')).toBe('grid');
    first.unmount();

    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));
    expect(toggle('Grid')).toHaveAttribute('aria-checked', 'true');
    expect(screen.queryByRole('region', { name: /projects table/i })).not.toBeInTheDocument();
  });

  it('keeps the status badge meaning identical in grid view', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));
    fireEvent.click(toggle('Grid'));

    // Two active, one inactive — same as the source data.
    expect(screen.getAllByText('Active')).toHaveLength(2);
    expect(screen.getAllByText('Inactive')).toHaveLength(1);
  });

  it('hides the toggle while there are no projects to view', () => {
    render(wrap(<ProjectsTable projects={[]} isLoading={false} error={null} />));
    expect(screen.queryByRole('radio', { name: 'Grid' })).not.toBeInTheDocument();
  });

  it('switches views from the keyboard', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));

    fireEvent.keyDown(toggle('List'), { key: 'ArrowRight' });
    expect(toggle('Grid')).toHaveAttribute('aria-checked', 'true');

    fireEvent.keyDown(toggle('Grid'), { key: 'ArrowLeft' });
    expect(toggle('List')).toHaveAttribute('aria-checked', 'true');
  });

  it('scopes the radio group so screen readers name what is being switched', () => {
    render(wrap(<ProjectsTable projects={PROJECTS} isLoading={false} error={null} />));
    const group = screen.getByRole('radiogroup');
    expect(group).toHaveAttribute('aria-label', expect.stringContaining('projects'));
    expect(within(group).getAllByRole('radio')).toHaveLength(2);
  });
});
