// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { uploadSbom } from '@/lib/api';

describe('uploadSbom', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends SBOM Version and Product Version as distinct snake_case form fields', async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: 'valid',
            workspace_id: 'workspace-1',
            validation_session_id: 'workspace-1',
            repair_workspace_url: '/repair/workspace-1',
            sbom_id: 123,
            sbom_name: 'manual-metadata',
            sbom_version: '1.1.1',
            product_version: '1.0.0',
            project_id: 42,
            spec: 'cyclonedx',
            spec_version: '1.5',
            file_size_bytes: 100,
            total_lines: 1,
            sha256: 'abc',
            is_large_file: false,
            full_editor_allowed: true,
            components: 0,
            validation_errors: [],
            validation_warnings: [],
            warnings: [],
            info: [],
            enrichment_status: 'pending',
          }),
          { status: 202, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: 123,
            sbom_name: 'manual-metadata',
            sbom_type: null,
            projectid: 42,
            project_id: 42,
            created_by: 'Feroze',
            created_on: '2026-07-02T00:00:00Z',
            modified_by: null,
            modified_on: null,
            sbom_version: '1.1.1',
            productver: '1.0.0',
            product_version: '1.0.0',
            status: 'validated',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

    await uploadSbom({
      sbom_name: 'manual-metadata',
      sbom_data: '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}',
      project_id: 42,
      sbom_version: '1.1.1',
      product_version: '1.0.0',
      created_by: 'Feroze',
    });

    const form = fetchMock.mock.calls[0][1].body as FormData;
    expect(form.get('sbom_version')).toBe('1.1.1');
    expect(form.get('product_version')).toBe('1.0.0');
    expect(form.get('created_by')).toBe('Feroze');
    expect(form.has('productver')).toBe(false);
    expect(form.has('sbomVersion')).toBe(false);
    expect(form.has('productVersion')).toBe(false);
  });
});
