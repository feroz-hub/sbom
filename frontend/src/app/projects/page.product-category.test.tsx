// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import {
  PRODUCT_CATEGORIES,
  getProductCategoryOption,
  isStandardProductCategory,
} from '@/lib/product-categories';
import type { Product, Project } from '@/types';

const api = vi.hoisted(() => ({
  createProduct: vi.fn(),
  updateProduct: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import { ProductFormDialog } from '@/components/products/ProductFormDialog';

const project: Project = {
  id: 7,
  project_name: 'Demo Project',
  project_details: null,
  project_status: 1,
  created_by: null,
  created_on: null,
  modified_by: null,
  modified_on: null,
};

function existingProduct(category: string | null): Product {
  return {
    id: 22,
    project_id: project.id,
    name: 'Clinical Gateway',
    description: 'Routes clinical data',
    vendor: 'Demo Vendor',
    category,
    status: 'active',
  };
}

function renderDialog(product?: Product) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <ProductFormDialog open project={project} product={product} onClose={vi.fn()} />
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe('Product category catalog', () => {
  it('provides every requested display value from one catalog', () => {
    expect(PRODUCT_CATEGORIES.map(({ label }) => label)).toEqual([
      'Medical Device Software',
      'Medical Device Gateway',
      'Embedded / Firmware',
      'IoT / Edge Device',
      'Enterprise Web Application',
      'API / Backend Service',
      'Microservice / Container Application',
      'Cloud / SaaS Application',
      'Desktop Application',
      'Mobile Application',
      'Library / SDK / Framework',
      'Database / Data Platform',
      'Operating System / Platform',
      'DevOps / Infrastructure Tool',
      'Security / Cybersecurity Platform',
      'AI / ML Application',
      'Other',
    ]);
    expect(getProductCategoryOption('Medical Device Gateway')?.code).toBe('MEDICAL_DEVICE_GATEWAY');
    expect(isStandardProductCategory('Legacy Healthcare Platform')).toBe(false);
  });
});

describe('ProductFormDialog category behavior', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.createProduct.mockResolvedValue(existingProduct(null));
    api.updateProduct.mockResolvedValue(existingProduct(null));
  });

  it('renders an accessible category dropdown with every catalog option', () => {
    renderDialog();

    const categorySelect = screen.getByRole('combobox', { name: 'Category' });
    expect(categorySelect).toHaveValue('');
    expect(within(categorySelect).getByRole('option', { name: 'Select product category' })).toBeDisabled();
    for (const category of PRODUCT_CATEGORIES) {
      expect(within(categorySelect).getByRole('option', { name: category.label })).toHaveValue(category.code);
    }
  });

  it('stores the display value when a standard category is selected', async () => {
    renderDialog();

    fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), {
      target: { value: 'Infusion Pump Gateway' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Category' }), {
      target: { value: 'MEDICAL_DEVICE_GATEWAY' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Product' }));

    await waitFor(() => expect(api.createProduct).toHaveBeenCalledWith(project.id, {
      name: 'Infusion Pump Gateway',
      description: null,
      vendor: null,
      category: 'Medical Device Gateway',
      status: 'active',
    }));
  });

  it('reveals Specify Category and prevents a blank custom category submission', async () => {
    renderDialog();

    fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), {
      target: { value: 'Custom Product' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Category' }), {
      target: { value: 'OTHER' },
    });
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Custom Product');
    expect(screen.getByRole('combobox', { name: 'Category' })).toHaveValue('OTHER');
    expect(screen.getByRole('textbox', { name: 'Specify Category' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create Product' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Specify category is required when Other is selected.',
    );
    expect(api.createProduct).not.toHaveBeenCalled();
  });

  it('trims and submits a custom category instead of the Other label', async () => {
    renderDialog();

    fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), {
      target: { value: 'Custom Product' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Category' }), {
      target: { value: 'OTHER' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Specify Category' }), {
      target: { value: '  Healthcare Integration Appliance  ' },
    });
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Custom Product');
    expect(screen.getByRole('textbox', { name: 'Specify Category' })).toHaveValue(
      '  Healthcare Integration Appliance  ',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create Product' }));

    await waitFor(() => expect(api.createProduct).toHaveBeenCalledWith(
      project.id,
      expect.objectContaining({ category: 'Healthcare Integration Appliance' }),
    ));
  });

  it('preselects a standard category while editing', async () => {
    renderDialog(existingProduct('API / Backend Service'));

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Category' })).toHaveValue('API_BACKEND_SERVICE'));
    expect(screen.queryByRole('textbox', { name: 'Specify Category' })).not.toBeInTheDocument();
  });

  it('shows and preserves a legacy category while editing without changes', async () => {
    renderDialog(existingProduct('Legacy Healthcare Platform'));

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Category' })).toHaveValue('OTHER'));
    expect(screen.getByRole('textbox', { name: 'Specify Category' })).toHaveValue('Legacy Healthcare Platform');
    fireEvent.click(screen.getByRole('button', { name: 'Save Product' }));

    await waitFor(() => expect(api.updateProduct).toHaveBeenCalledWith(
      22,
      expect.objectContaining({ category: 'Legacy Healthcare Platform' }),
    ));
  });

  it('keeps a null existing category unselected', async () => {
    renderDialog(existingProduct(null));

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Category' })).toHaveValue(''));
    expect(screen.queryByRole('textbox', { name: 'Specify Category' })).not.toBeInTheDocument();
  });
});
