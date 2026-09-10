// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Suspense } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

const api = vi.hoisted(() => ({
  getProduct: vi.fn(),
  getProductSboms: vi.fn(),
  updateProduct: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title }: { title: string }) => <h1>{title}</h1> }));
vi.mock('@/components/reports/NotifyMeLink', () => ({ NotifyMeLink: () => null }));
vi.mock('@/components/schedules/ScheduleCard', () => ({
  ScheduleCard: ({ scope, targetId }: { scope: string; targetId: number }) => (
    <div data-testid="schedule-card">{scope}:{targetId}</div>
  ),
}));
vi.mock('@/components/sboms/SbomUploadModal', () => ({ SbomUploadModal: () => null }));
vi.mock('@/components/sboms/SbomStatusBadge', () => ({ SbomStatusBadge: () => <span>Not analyzed</span> }));
vi.mock('@/hooks/useAnalysisStream', () => ({
  useAnalysisStream: () => ({ state: { phase: 'idle' }, startAnalysis: vi.fn() }),
}));

import ProductDetailPage from './page';

const routeParams = Promise.resolve({ id: '22' });
const product = {
  id: 22,
  tenant_id: 1,
  project_id: 3,
  name: 'Infusion Pump Controller',
  normalized_name: 'infusion pump controller',
  slug: 'infusion-pump-controller',
  description: null,
  product_key: null,
  vendor: null,
  category: null,
  status: 'active',
  latest_version: '2.0',
  current_sbom_id: 81,
  current_sbom_name: 'controller.cdx',
  current_sbom_version: '2.0',
  metadata_json: {},
  created_by: null,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  deleted_at: null,
  sbom_count: 2,
  latest_sbom_version: '2.0',
};
const sboms = [
  { id: 80, tenant_id: 1, projectid: 3, product_id: 22, sbom_name: 'controller.cdx', sbom_version: '1.0', productver: '1.0', created_on: '2026-08-01T00:00:00Z' },
  { id: 81, tenant_id: 1, projectid: 3, product_id: 22, sbom_name: 'controller.cdx', sbom_version: '2.0', productver: '2.0', created_on: '2026-09-01T00:00:00Z' },
];

async function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <Suspense fallback={<div>Loading…</div>}>
            <ProductDetailPage params={routeParams} />
          </Suspense>
        </ToastProvider>
      </QueryClientProvider>,
    );
  });
}

describe('ProductDetailPage scheduler hierarchy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getProduct.mockResolvedValue(product);
    api.getProductSboms.mockResolvedValue(sboms);
    api.updateProduct.mockResolvedValue(product);
  });

  it('shows the explicit current SBOM and Product schedule controls', async () => {
    await renderPage();

    const select = await screen.findByLabelText(/current version used by current_only schedules/i);
    expect(select).toHaveValue('81');
    expect(screen.getByTestId('schedule-card')).toHaveTextContent('PRODUCT:22');
  });

  it('changes current SBOM through the Product API', async () => {
    await renderPage();
    const user = userEvent.setup();
    await user.selectOptions(
      await screen.findByLabelText(/current version used by current_only schedules/i),
      '80',
    );

    await waitFor(() => expect(api.updateProduct).toHaveBeenCalledWith(22, { current_sbom_id: 80 }));
  });
});
