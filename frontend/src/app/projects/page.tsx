'use client';

import { Suspense, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, Pencil, Plus, Trash2, Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ProjectsTable } from '@/components/projects/ProjectsTable';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { ProductFormDialog } from '@/components/products/ProductFormDialog';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { deleteProduct, getDashboardScannedProjectIds, getEffectiveProductSchedule, getProducts, getProjects, type DashboardFilterScope } from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { invalidateDashboardTiles, invalidateProductSurfaces } from '@/lib/queryInvalidation';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import type { Product, Project } from '@/types';

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
      invalidateProductSurfaces(queryClient, deletedProduct.id);
      invalidateDashboardTiles(queryClient);
      showSuccess(`Application “${deletedProduct.name}” was deleted successfully.`);
      setDeleteProductTarget(null);
    },
    onError: (error: unknown) => showError(getApiErrorMessage(error, 'Application deletion failed. Please try again.')),
  });

  const handleUploadSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['products', project.id] });
  };

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <CardTitle>{project.project_name}</CardTitle>
        <Button size="sm" variant="secondary" onClick={() => setFormOpen(true)}>
          <Plus className="h-4 w-4" />
          Create Application
        </Button>
      </CardHeader>
      <CardContent>
        <Table ariaLabel={`${project.project_name} applications`}>
          <TableHead>
            <tr>
              <Th>Application Name</Th>
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
              <EmptyRow cols={9} message="Loading applications..." />
            ) : products.length === 0 ? (
              <EmptyRow cols={9} message="No applications found for this project. Create one before uploading SBOMs." />
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
                      <span title="CURRENT_ONLY schedules skip this application until a current SBOM is selected.">Not set</span>
                    )}
                  </Td>
                  <Td><ProductScheduleStatus productId={product.id} /></Td>
                  <Td className="text-hcl-muted">{product.status || 'active'}</Td>
                  <Td>
                    <div className="flex justify-end gap-1.5">
                      <Link
                        href={`/products/${product.id}`}
                        className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-transparent text-hcl-navy transition-colors hover:bg-surface-muted hover:text-hcl-blue"
                        title="View application"
                      >
                        <Eye className="h-4 w-4" />
                      </Link>
                      <Button size="icon" variant="ghost" title="Edit application" onClick={() => setEditingProduct(product)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button size="icon" variant="ghost" title="Upload SBOM" onClick={() => setUploadProduct(product)}>
                        <Upload className="h-4 w-4" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        title="Delete application"
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
        recordKind="application"
        allowPermanent={false}
        title={`Delete application “${deleteProductTarget?.name ?? ''}”?`}
      />
    </Card>
  );
}

export default function ProjectsPage() {
  return <Suspense fallback={null}><ProjectsContent /></Suspense>;
}

function ProjectsContent() {
  const [showCreate, setShowCreate] = useState(false);
  const params = useSearchParams();
  const projectId = Number(params?.get('project')) || null;
  const applicationId = projectId ? Number(params?.get('product')) || null : null;
  const sbomId = applicationId ? Number(params?.get('sbom')) || null : null;
  const scanned = params?.get('scanned') === '1';
  const scope: DashboardFilterScope = { projectId, applicationId, sbomId };

  const { data: projects, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });
  const scannedProjects = useQuery({
    queryKey: ['dashboard-scanned-projects', projectId, applicationId, sbomId],
    queryFn: ({ signal }) => getDashboardScannedProjectIds(scope, signal),
    enabled: scanned,
  });
  const scannedIds = scanned ? new Set(scannedProjects.data?.ids ?? []) : null;
  const visibleProjects = projects?.filter((project) =>
    (!projectId || project.id === projectId) && (!scannedIds || scannedIds.has(project.id)),
  );
  const pageLoading = isLoading || (scanned && scannedProjects.isLoading);
  const pageError = error || (scanned ? scannedProjects.error : null);

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
          projects={visibleProjects}
          isLoading={pageLoading}
          error={pageError}
        />
        {!pageLoading && !pageError && visibleProjects?.length ? (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-hcl-navy">Applications</h2>
            {visibleProjects.map((project) => (
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
