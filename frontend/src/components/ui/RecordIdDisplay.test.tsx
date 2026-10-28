// @vitest-environment jsdom
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RecordIdDisplay, recordIdLabel } from './RecordIdDisplay';

describe('persisted record display labels', () => {
  it('renders the exact persisted integer, independently of the UUID link', () => {
    const uuid = 'f5e7f4c4-8a16-4c70-93d8-092173885437';
    render(<a href={`/sboms/${uuid}`}><RecordIdDisplay kind="SBOM" displayId={567} /></a>);
    expect(screen.getByText('SBOM #567').closest('a')).toHaveAttribute('href', `/sboms/${uuid}`);
    expect(screen.getByLabelText('SBOM ID 567')).toBeVisible();
    expect(screen.queryByText(uuid)).not.toBeInTheDocument();
  });

  it.each([undefined, null, 0, -1, 1.5, NaN, Infinity, 2 ** 53])('never fabricates an invalid or missing ID: %s', value => {
    render(<RecordIdDisplay kind="Project" displayId={value} />);
    expect(screen.getByLabelText('Project ID unavailable')).toHaveTextContent('Project —');
  });

  it.each(['123', 'f5e7f4c4-8a16-4c70-93d8-092173885437', true])('never parses a selector into a label', value => {
    expect(recordIdLabel('Run', value)).toBe('Run —');
  });
});
