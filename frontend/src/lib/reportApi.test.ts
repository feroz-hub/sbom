// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./auth', () => ({ getActiveTenantId: () => 'tenant-17' }));
vi.mock('./env', () => ({ resolveBaseUrl: () => 'http://localhost:8000' }));
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.resetModules(); });

describe('Report BFF contracts', () => {
  it('sends JSON and tenant headers through authenticated same-origin BFF', async () => {
    vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true');
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 1 }), { status: 201, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const { createReportSubscription } = await import('./reportApi');
    const { defaultReportPreferences } = await import('@/components/reports/ReportNotificationsPage');
    await createReportSubscription(defaultReportPreferences('TENANT'));
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/backend/api/report-subscriptions');
    const headers = new Headers(options.headers);
    expect(headers.get('X-Tenant-ID')).toBe('tenant-17');
    expect(headers.get('Content-Type')).toContain('application/json');
    expect(url).not.toContain('token');
    expect(JSON.parse(options.body)).not.toHaveProperty('recipient_email');
  });
  it('uses the same authenticated transport for artifact downloads', async () => {
    vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true');
    const fetchMock = vi.fn().mockResolvedValue(new Response('%PDF', { status: 200, headers: { 'Content-Disposition': 'attachment; filename="report.pdf"' } }));
    vi.stubGlobal('fetch', fetchMock);
    const { downloadReportArtifact } = await import('./reportApi');
    await downloadReportArtifact(4, 9);
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/backend/api/report-deliveries/4/artifacts/9');
    expect(new Headers(options.headers).get('X-Tenant-ID')).toBe('tenant-17');
    expect(options.method).toBe('GET');
  });
});
