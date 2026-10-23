import { afterEach, expect, it, vi } from 'vitest';
import { getRunsPage, exportRunsJson } from './api';

afterEach(() => { vi.unstubAllGlobals(); });
it('reads server count and preserves public selectors, search and order', async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'run-uuid' }]), { headers: { 'X-Total-Count': '123' } }));
  vi.stubGlobal('fetch', fetch);
  const page = await getRunsPage({ project_id: 'project-uuid', sbom_id: 'sbom-uuid', page: 5, page_size: 25, q: 'Gateway 2', sort_by: 'completed_on', sort_direction: 'desc', summary_only: true });
  expect(page.total).toBe(123);
  expect(page.items).toEqual([{ id: 'run-uuid' }]);
  const url = new URL(String(fetch.mock.calls[0][0]), 'https://example.test');
  expect(Object.fromEntries(url.searchParams)).toMatchObject({ project_id: 'project-uuid', sbom_id: 'sbom-uuid', page: '5', page_size: '25', q: 'Gateway 2', sort_by: 'completed_on', summary_only: 'true' });
});
it('does not fabricate a page total when the header is missing', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('[]')));
  await expect(getRunsPage()).rejects.toThrow('pagination count is unavailable');
});
it('JSON export keeps server search and status filters', async () => {
  const fetch = vi.fn().mockResolvedValue(new Response('[]'));
  vi.stubGlobal('fetch', fetch);
  await expect(exportRunsJson({ q: 'Gateway', run_status: 'PARTIAL', project_id: 'project-uuid' })).rejects.toThrow('No analysis runs match');
  const url = new URL(String(fetch.mock.calls[0][0]), 'https://example.test');
  expect(Object.fromEntries(url.searchParams)).toMatchObject({ q: 'Gateway', run_status: 'PARTIAL', project_id: 'project-uuid' });
});
