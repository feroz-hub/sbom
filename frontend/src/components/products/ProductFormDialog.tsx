'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/Button';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useNotifications } from '@/hooks/useNotifications';
import { createProduct, updateProduct } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';
import {
  CUSTOM_PRODUCT_CATEGORY_CODE,
  getProductCategoryFormValue,
  PRODUCT_CATEGORIES,
  PRODUCT_CATEGORY_MAX_LENGTH,
  resolveProductCategory,
  type ProductCategorySelection,
} from '@/lib/product-categories';
import type { Product, Project } from '@/types';

type ProductFormState = {
  name: string;
  description: string;
  vendor: string;
  selectedCategory: ProductCategorySelection;
  customCategory: string;
  status: string;
};

const emptyProductForm: ProductFormState = {
  name: '',
  description: '',
  vendor: '',
  selectedCategory: '',
  customCategory: '',
  status: 'active',
};

interface ProductFormDialogProps {
  open: boolean;
  project: Project | null;
  product?: Product | null;
  onClose: () => void;
}

export function ProductFormDialog({ open, project, product, onClose }: ProductFormDialogProps) {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [form, setForm] = useState<ProductFormState>(emptyProductForm);
  const [categoryError, setCategoryError] = useState<string>();

  const mutation = useMutation({
    mutationFn: (category: string | null) => {
      if (!project) throw new Error('Project is required');
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        vendor: form.vendor.trim() || null,
        category,
        status: form.status,
      };
      return product ? updateProduct(product.id, payload) : createProduct(project.id, payload);
    },
    onSuccess: () => {
      if (project) queryClient.invalidateQueries({ queryKey: ['products', project.id] });
      showSuccess(`Product “${form.name.trim()}” was ${product ? 'updated' : 'created'} successfully.`);
      onClose();
    },
    onError: (error: unknown) => showError(getApiErrorMessage(error, 'Product save failed. Please try again.')),
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!form.name.trim()) return;
    const category = resolveProductCategory(form.selectedCategory, form.customCategory);
    if (form.selectedCategory === CUSTOM_PRODUCT_CATEGORY_CODE && !category) {
      setCategoryError('Specify category is required when Other is selected.');
      return;
    }
    setCategoryError(undefined);
    mutation.mutate(category);
  };

  useEffect(() => {
    if (!open) return;
    if (product) {
      setForm({
        name: product.name,
        description: product.description ?? '',
        vendor: product.vendor ?? '',
        ...getProductCategoryFormValue(product.category),
        status: product.status ?? 'active',
      });
    } else {
      setForm(emptyProductForm);
    }
    setCategoryError(undefined);
  }, [open, product]);

  const resetAndClose = () => {
    setForm(emptyProductForm);
    setCategoryError(undefined);
    onClose();
  };

  return (
    <Dialog open={open} onClose={resetAndClose} title={product ? 'Edit Product' : 'Create Product'} maxWidth="lg">
      <form onSubmit={handleSubmit} noValidate>
        <DialogBody className="space-y-4">
          <Input
            label="Name"
            required
            value={form.name}
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
          />
          <Textarea
            label="Description"
            value={form.description}
            onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
          />
          <div className="grid gap-4 sm:grid-cols-3">
            <Input
              label="Vendor"
              value={form.vendor}
              onChange={(event) => setForm((current) => ({ ...current, vendor: event.target.value }))}
            />
            <div className="space-y-4">
              <Select
                label="Category"
                placeholder="Select product category"
                value={form.selectedCategory}
                className={form.selectedCategory ? undefined : 'text-hcl-muted'}
                onChange={(event) => {
                  const selectedCategory = event.target.value as ProductCategorySelection;
                  setForm((current) => ({ ...current, selectedCategory }));
                  if (selectedCategory !== CUSTOM_PRODUCT_CATEGORY_CODE) setCategoryError(undefined);
                }}
              >
                {PRODUCT_CATEGORIES.map((category) => (
                  <option key={category.code} value={category.code}>
                    {category.label}
                  </option>
                ))}
              </Select>
              {form.selectedCategory === CUSTOM_PRODUCT_CATEGORY_CODE ? (
                <Input
                  label="Specify Category"
                  required
                  maxLength={PRODUCT_CATEGORY_MAX_LENGTH}
                  value={form.customCategory}
                  error={categoryError}
                  onChange={(event) => {
                    const customCategory = event.target.value;
                    setForm((current) => ({ ...current, customCategory }));
                    if (customCategory.trim()) setCategoryError(undefined);
                  }}
                />
              ) : null}
            </div>
            <Select
              label="Status"
              value={form.status}
              onChange={(event) => setForm((current) => ({ ...current, status: event.target.value }))}
            >
              <option value="active">Active</option>
              <option value="maintenance">Maintenance</option>
              <option value="retired">Retired</option>
            </Select>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={resetAndClose}>
            Cancel
          </Button>
          <Button type="submit" loading={mutation.isPending} disabled={!form.name.trim()}>
            {product ? 'Save Product' : 'Create Product'}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
