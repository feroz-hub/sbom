'use client';

import { useEffect, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, Pencil, Plus, Trash2, Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ProjectsTable } from '@/components/projects/ProjectsTable';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { createProduct, deleteProduct, getEffectiveProductSchedule, getProducts, getProjects, updateProduct } from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import type { Product, Project, SBOMSource } from '@/types';

type ProductFormState = {
  name: string;
  description: string;
  vendor: string;
  category: string;
  status: string;
};

const emptyProductForm: ProductFormState = {
  name: '',
  description: '',
  vendor: '',
  category: '',
  status: 'active',
};

function ProductScheduleStatus({ productId }: { productId: number }) {
  const query = useQuery({
    queryKey: ['schedule', 'PRODUCT', productId],
    queryFn: ({ signal }) => getEffectiveProductSchedule(productId, signal),
  });
  if (query.isLoading) return <span className="text-xs text-hcl-muted">Loading…</span>;
  if (query.error || !query.data?.schedule) return <Badge variant="gray">None</Badge>;
  const state = query.data.state;
  return (
    <div className="space-y-1">
      <Badge variant={state === 'CUSTOM' || state === 'INHERITED' ? 'success' : 'gray'}>
        {state.toLowerCase()}
      </Badge>
      <p className="text-xs text-hcl-muted">
        {query.data.schedule.cadence.toLowerCase()} · {query.data.source_scope?.toLowerCase()}
      </p>
    </div>
  );
}

function ProductFormDialog({
  open,
  project,
  product,
  onClose,
}: {
  open: boolean;
  project: Project | null;
  product?: Product | null;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [form, setForm] = useState<ProductFormState>(emptyProductForm);

  const mutation = useMutation({
    mutationFn: () => {
      if (!project) throw new Error('Project is required');
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        vendor: form.vendor.trim() || null,
        category: form.category.trim() || null,
        status: form.status,
      };
      return product ? updateProduct(product.id, payload) : createProduct(project.id, payload);
    },
    onSuccess: (_result, _variables) => {
      if (project) queryClient.invalidateQueries({ queryKey: ['products', project.id] });
      showSuccess(`Product “${form.name.trim()}” was ${product ? 'updated' : 'created'} successfully.`);
      onClose();
    },
    onError: (error: unknown) => showError(getApiErrorMessage(error, 'Product save failed. Please try again.')),
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!form.name.trim()) return;
    mutation.mutate();
  };

  useEffect(() => {
    if (!open) return;
    setForm(
      product
        ? {
            name: product.name,
            description: product.description ?? '',
            vendor: product.vendor ?? '',
            category: product.category ?? '',
            status: product.status ?? 'active',
          }
        : emptyProductForm,
    );
  }, [open, product]);

  return (
    <Dialog
      open={open}
      onClose={() => {
        setForm(emptyProductForm);
        onClose();
      }}
      title={product ? 'Edit Product' : 'Create Product'}
      maxWidth="lg"
    >
      <form onSubmit={handleSubmit}>
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
            <Input
              label="Category"
              value={form.category}
              onChange={(event) => setForm((current) => ({ ...current, category: event.target.value }))}
            />
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
          <Button
            variant="secondary"
            onClick={() => {
              setForm(emptyProductForm);
              onClose();
            }}
          >
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

function ProjectProducts({ project }: { project: Project }) {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [formOpen, setFormOpen] = useState(false);
  const [editingProduct, setEditingProduct] = useState<Product | null>(null);
  const [uploadProduct, setUploadProduct] = useState<Product | null>(null);
  const [deleteProductTarget, setDeleteProductTarget] = useState<Product | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['products', project.id],
    queryFn: ({ signal }) => getProducts(project.id, signal),
  });
  const products = data?.items ?? [];

  const deleteMutation = useMutation({
    mutationFn: (product: Product) => deleteProduct(product.id),
    onSuccess: (_data, deletedProduct) => {
      queryClient.invalidateQueries({ queryKey: ['products', project.id] });
      showSuccess(`Product “${deletedProduct.name}” was deleted successfully.`);
      setDeleteProductTarget(null);
    },
    onError: (error: unknown) => showError(getApiErrorMessage(error, 'Product deletion failed. Please try again.')),
  });

  const handleUploadSuccess = (_sbom: SBOMSource) => {
    queryClient.invalidateQueries({ queryKey: ['products', project.id] });
  };

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <CardTitle>{project.project_name}</CardTitle>
        <Button size="sm" variant="secondary" onClick={() => setFormOpen(true)}>
          <Plus className="h-4 w-4" />
          Create Product
        </Button>
      </CardHeader>
      <CardContent>
        <Table ariaLabel={`${project.project_name} products`}>
          <TableHead>
            <tr>
              <Th>Product Name</Th>
              <Th>Description</Th>
              <Th>SBOM Count</Th>
              <Th>Latest SBOM</Th>
              <Th>Latest Version</Th>
              <Th>Current SBOM</Th>
              <Th>Schedule</Th>
              <Th>Status</Th>
              <Th className="text-right">Actions</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <EmptyRow cols={9} message="Loading products..." />
            ) : products.length === 0 ? (
              <EmptyRow cols={9} message="No products found for this project. Create one before uploading SBOMs." />
            ) : (
              products.map((product) => (
                <tr key={product.id}>
                  <Td>
                    <Link href={`/products/${product.id}`} className="font-medium text-hcl-navy hover:text-hcl-blue hover:underline">
                      {product.name}
                    </Link>
                  </Td>
                  <Td className="max-w-[260px] truncate text-hcl-muted">{product.description || '—'}</Td>
                  <Td className="text-hcl-muted">{product.sbom_count ?? 0}</Td>
                  <Td className="text-hcl-muted">
                    {product.latest_sbom_id ? (
                      <Link href={`/sboms/${product.latest_sbom_id}`} className="hover:text-hcl-blue hover:underline">
                        #{product.latest_sbom_id}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </Td>
                  <Td className="text-hcl-muted">{product.latest_sbom_version || '—'}</Td>
                  <Td className="text-hcl-muted">
                    {product.current_sbom_id ? (
                      <Link href={`/sboms/${product.current_sbom_id}`} className="hover:text-hcl-blue hover:underline">
                        {product.current_sbom_version || `#${product.current_sbom_id}`}
                      </Link>
                    ) : (
                      <span title="CURRENT_ONLY schedules skip this product until a current SBOM is selected.">Not set</span>
                    )}
                  </Td>
                  <Td><ProductScheduleStatus productId={product.id} /></Td>
                  <Td className="text-hcl-muted">{product.status || 'active'}</Td>
                  <Td>
                    <div className="flex justify-end gap-1.5">
                      <Link
                        href={`/products/${product.id}`}
                        className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-transparent text-hcl-navy transition-colors hover:bg-surface-muted hover:text-hcl-blue"
                        title="View product"
                      >
                        <Eye className="h-4 w-4" />
                      </Link>
                      <Button size="icon" variant="ghost" title="Edit product" onClick={() => setEditingProduct(product)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button size="icon" variant="ghost" title="Upload SBOM" onClick={() => setUploadProduct(product)}>
                        <Upload className="h-4 w-4" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        title="Delete product"
                        onClick={() => setDeleteProductTarget(product)}
                        disabled={deleteMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>

      <ProductFormDialog
        open={formOpen || editingProduct !== null}
        project={project}
        product={editingProduct}
        onClose={() => {
          setFormOpen(false);
          setEditingProduct(null);
        }}
      />
      <SbomUploadModal
        open={uploadProduct !== null}
        onClose={() => setUploadProduct(null)}
        initialProjectId={project.id}
        initialProductId={uploadProduct?.id}
        onSuccess={handleUploadSuccess}
      />
      <DeleteConfirmDialog
        open={deleteProductTarget !== null}
        onClose={() => !deleteMutation.isPending && setDeleteProductTarget(null)}
        onConfirm={() => deleteProductTarget && deleteMutation.mutate(deleteProductTarget)}
        loading={deleteMutation.isPending}
        recordName={deleteProductTarget?.name ?? ''}
        recordKind="product"
        allowPermanent={false}
        title={`Delete product “${deleteProductTarget?.name ?? ''}”?`}
      />
    </Card>
  );
}

export default function ProjectsPage() {
  const [showCreate, setShowCreate] = useState(false);

  const { data: projects, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Projects"
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New Project
          </Button>
        }
      />
      <div className="space-y-6 p-6">
        <ProjectsTable
          projects={projects}
          isLoading={isLoading}
          error={error}
        />
        {!isLoading && !error && projects?.length ? (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-hcl-navy">Products</h2>
            {projects.map((project) => (
              <ProjectProducts key={project.id} project={project} />
            ))}
          </div>
        ) : null}
      </div>

      <ProjectModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
      />
    </div>
  );
}
