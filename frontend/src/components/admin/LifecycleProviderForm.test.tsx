// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { LifecycleProviderForm } from './LifecycleProviderForm';
import { makeProvider } from '@/test/lifecycle-provider-fixtures';

function setup(overrides: Partial<React.ComponentProps<typeof LifecycleProviderForm>> = {}) {
  const onSave = vi.fn().mockResolvedValue(undefined); const onSaveSecret = vi.fn().mockResolvedValue(undefined);
  const provider = makeProvider({ provider_key: 'xeol_db', display_name: 'Local Xeol DB', base_url: null, config: { db_path: '/approved/xeol.db' } }, { network: false, editable_endpoint: false, effective_endpoint: null, config_fields: ['db_path'], data_source_type: 'Local DB' });
  const props = { provider, onClose: vi.fn(), onSave, onSaveSecret, onDeleteSecret: vi.fn().mockResolvedValue(undefined), ...overrides };
  const view = render(<LifecycleProviderForm {...props} />);
  return { ...view, props, onSave, onSaveSecret };
}
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }

describe('provider configuration form', () => {
  it('shows guided source fields and effective cache defaults, omits network controls', () => {
    setup(); expect(screen.getByLabelText('Database path')).toHaveValue('/approved/xeol.db');
    expect(screen.queryByLabelText('Timeout (seconds)')).not.toBeInTheDocument();
    expect(screen.getAllByText('Effective default: 14')).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });
  it.each(['{broken draft', '[]', 'null'])('rejects invalid advanced JSON and preserves %s', async value => {
    const h = setup(); await userEvent.click(screen.getByRole('button', { name: 'Advanced configuration' }));
    change('Configuration JSON', value); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(h.onSave).not.toHaveBeenCalled(); expect(screen.getByRole('alert')).toHaveTextContent('valid JSON object');
    expect(screen.getByLabelText('Configuration JSON')).toHaveValue(value);
    expect(screen.getByLabelText('Configuration JSON')).toHaveAttribute('aria-invalid', 'true');
  });
  it('validates numbers inline without sending a request', async () => {
    const h = setup(); change('Priority', '0'); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(screen.getByLabelText('Priority')).toHaveAttribute('aria-invalid', 'true'); expect(h.onSave).not.toHaveBeenCalled();
  });
  it('validates feed URLs and keeps the draft', async () => {
    const h = setup({ provider: makeProvider({}, { feed_urls: true, editable_endpoint: false, effective_endpoint: null }) });
    change('Feed URLs', 'http://unsafe.example/feed'); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(screen.getByLabelText('Feed URLs')).toHaveAttribute('aria-invalid', 'true'); expect(h.onSave).not.toHaveBeenCalled();
  });
  it('shows a built-in endpoint read-only and hides unsupported JSON', () => {
    setup({ provider: makeProvider({ base_url: null }, { editable_endpoint: false }) });
    expect(screen.getByText('Effective source · read-only')).toBeInTheDocument();
    expect(screen.queryByLabelText('Endpoint URL')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Configuration JSON')).not.toBeInTheDocument();
  });
  it('saves only supported fields and reports saved state', async () => {
    const h = setup(); change('Database path', '/approved/new.db'); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(h.onSave).toHaveBeenCalledWith('xeol_db', expect.objectContaining({ config: { db_path: '/approved/new.db' } })));
    expect(h.onSave.mock.calls[0][1]).not.toHaveProperty('base_url'); expect(h.onSave.mock.calls[0][1]).not.toHaveProperty('timeout_seconds');
    expect(screen.getByRole('status')).toHaveTextContent('Changes saved.');
  });
  it('preserves a draft after a failed save', async () => {
    const onSave = vi.fn().mockRejectedValue(new Error('request failed')); setup({ onSave }); change('Priority', '27');
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('draft is preserved'); expect(screen.getByLabelText('Priority')).toHaveValue(27);
  });
  it('prevents duplicate submissions while saving', async () => {
    let finish!: () => void; const onSave = vi.fn().mockImplementation(() => new Promise<void>(resolve => { finish = resolve; })); setup({ onSave });
    change('Priority', '27'); await userEvent.dblClick(screen.getByRole('button', { name: 'Save changes' })); expect(onSave).toHaveBeenCalledTimes(1); finish();
  });
  it('keeps drafts when verification or credentials update provider props', () => {
    const h = setup(); change('Priority', '27'); h.rerender(<LifecycleProviderForm {...h.props} provider={{ ...h.props.provider, has_secret: true }} />);
    expect(screen.getByLabelText('Priority')).toHaveValue(27);
  });
  it('masks saved credentials and clears a newly saved credential', async () => {
    const h = setup({ provider: makeProvider({ has_secret: true }, { secret_name: 'api_key' }) });
    expect(screen.getByText('Credential configured')).toBeInTheDocument(); expect(screen.getByLabelText('Provider credential')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('Provider credential')).toHaveValue(''); change('Provider credential', 'synthetic-credential');
    await userEvent.click(screen.getByRole('button', { name: 'Save credential' })); await waitFor(() => expect(h.onSaveSecret).toHaveBeenCalled()); expect(screen.getByLabelText('Provider credential')).toHaveValue('');
  });
  it('requires confirmation before clearing a credential', async () => {
    const onDeleteSecret = vi.fn().mockResolvedValue(undefined); setup({ provider: makeProvider({ has_secret: true }, { secret_name: 'api_key' }), onDeleteSecret });
    await userEvent.click(screen.getByRole('button', { name: 'Clear credential' })); expect(onDeleteSecret).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm clear' })); await waitFor(() => expect(onDeleteSecret).toHaveBeenCalled());
  });
  it('explains platform disable impact before saving', async () => {
    const h = setup(); await userEvent.click(screen.getByLabelText('Enabled')); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(h.onSave).not.toHaveBeenCalled(); expect(screen.getByRole('alert')).toHaveTextContent('Tenants inheriting this setting');
    await userEvent.click(screen.getByRole('button', { name: 'Disable and save' })); await waitFor(() => expect(h.onSave).toHaveBeenCalled());
  });
  it('honors read-only permissions', () => { setup({ readOnly: true }); expect(screen.getByLabelText('Priority')).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument(); });
});
