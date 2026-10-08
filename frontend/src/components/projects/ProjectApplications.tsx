'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { usePermission } from '@/hooks/usePermission';
import { PermissionGate } from '@/components/ui/PermissionGate';
import { PermissionButton as Button } from '@/components/ui/PermissionButton';
import { Badge } from '@/components/ui/Badge';
import { ProductFormDialog } from '@/components/products/ProductFormDialog';
import { Card, CardContent, CardHeader } from '@/components/ui/Card';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { deleteProduct, getEffectiveProductSchedule, getProducts } from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { invalidateDashboardTiles, invalidateProductSurfaces } from '@/lib/queryInvalidation';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import type { Product, Project } from '@/types';

import { Alert } from '@/components/ui/Alert';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { InventoryActionMenu } from './InventoryActionMenu';
import { usePagination } from '@/hooks/usePagination';
import { Pagination } from '@/components/ui/Pagination';
function ProductScheduleStatus({ productId }: { productId: number }) {
  const canRead = usePermission("schedule:read");
  const query = useQuery({
    queryKey: ['schedule', 'PRODUCT', productId],
    enabled: canRead,
    queryFn: ({ signal }) => getEffectiveProductSchedule(productId, signal),
  });
  if (!canRead) return <span className="text-xs text-hcl-muted">Schedule access restricted</span>;
  if (query.isLoading) return <span className="text-xs text-hcl-muted">Loading…</span>;
  if (query.error || !query.data?.schedule) return <span className="text-xs text-hcl-muted">No schedule</span>;
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

export function ProjectApplications({ project }: { project: Project }) {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [formOpen, setFormOpen] = useState(false);
  const [editingProduct, setEditingProduct] = useState<Product | null>(null);
  const [uploadProduct, setUploadProduct] = useState<Product | null>(null);
  const [deleteProductTarget, setDeleteProductTarget] = useState<Product | null>(null);

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const { data, isLoading, error } = useQuery({
    queryKey: ['products', project.id],
    queryFn: ({ signal }) => getProducts(project.id, signal),
  });
  const products = useMemo(() => data?.items ?? [], [data]);
  const filtered = useMemo(() => products.filter(product => (statusFilter === 'all' || (product.status || 'active') === statusFilter) && `${product.name} ${product.description || ''} ${product.id}`.toLowerCase().includes(search.trim().toLowerCase())), [products, search, statusFilter]);
  const pagination = usePagination(filtered, { defaultPageSize: 25 });
  const statuses = Array.from(new Set(products.map(product => product.status || 'active')));
  function changeSearch(value: string) { setSearch(value); pagination.resetPage(); }
  function changeStatus(value: string) { setStatusFilter(value); pagination.resetPage(); }

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

  function applicationActions(product: Product) {
    return <InventoryActionMenu label={`Actions for application ${product.name}`} actions={[
      { label: 'View application', permission: 'product:read', href: `/products/${product.id}` },
      { label: 'Edit application', permission: 'product:update', onClick: () => setEditingProduct(product) },
      { label: 'Upload SBOM', permission: ['sbom:upload', 'product:assign_sbom'], onClick: () => setUploadProduct(product) },
      { label: 'Schedule', permission: 'schedule:read', href: `/products/${product.id}` },
      { label: 'Delete application', permission: 'product:delete', onClick: () => setDeleteProductTarget(product), destructive: true, disabled: deleteMutation.isPending },
    ]} />;
  }
  function status(product: Product) { const value = product.status || 'active'; return <Badge variant={value === 'active' ? 'success' : 'gray'}>{value.toUpperCase()}</Badge>; }
  function latest(product: Product) { return <div>{product.latest_sbom_id ? <Link href={`/sboms/${product.latest_sbom_id}`} className="font-medium text-hcl-blue hover:underline">#{product.latest_sbom_id}</Link> : '—'}<p className="mt-1 text-xs text-hcl-muted">{product.latest_sbom_version || '—'}</p></div>; }
  function current(product: Product) { return product.current_sbom_id ? <Link href={`/sboms/${product.current_sbom_id}`} className="text-hcl-blue hover:underline">{product.current_sbom_version || `#${product.current_sbom_id}`}</Link> : <span title="CURRENT_ONLY schedules skip this application until a current SBOM is selected." className="text-hcl-muted">Not set</span>; }
  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0"><h2 className="text-base font-semibold text-hcl-navy">Applications</h2><p className="mt-1 truncate text-sm font-medium text-foreground" title={project.project_name}>{project.project_name}</p><p className="mt-1 text-xs text-hcl-muted" aria-live="polite">{isLoading ? 'Loading applications…' : `${data?.total ?? 0} ${(data?.total ?? 0) === 1 ? 'application' : 'applications'}`}</p></div>
        <Button permission={"product:create"} size="sm" onClick={() => setFormOpen(true)}><Plus className="h-4 w-4" />Create Application</Button>
      </CardHeader>
      <CardContent>
        {!isLoading && !error && products.length > 0 && <div className="mb-4 flex flex-col gap-3 sm:flex-row"><Input aria-label="Search applications" placeholder="Search applications…" value={search} onChange={event => changeSearch(event.target.value)} className="sm:max-w-sm" /><Select aria-label="Application status" value={statusFilter} onChange={event => changeStatus(event.target.value)} className="sm:max-w-[180px]"><option value="all">All statuses</option>{statuses.map(value => <option key={value} value={value}>{value}</option>)}</Select></div>}
        {error ? <Alert variant="error" title="Could not load applications">{getApiErrorMessage(error, 'Applications could not be loaded. Please try again.')}</Alert> : isLoading ? <p role="status" className="py-6 text-sm text-hcl-muted">Loading applications…</p> : products.length === 0 ? <div className="py-8 text-center"><h3 className="font-semibold text-hcl-navy">No applications in this project</h3><p className="mt-2 text-sm text-hcl-muted">Applications organize this project’s SBOMs.</p><PermissionGate permission="product:create"><Button permission={"product:create"} className="mt-4" size="sm" variant="secondary" onClick={() => setFormOpen(true)}>Create Application</Button></PermissionGate></div> : <>
          <div className="hidden md:block"><Table ariaLabel={`${project.project_name} applications`}><TableHead><tr><Th>Application</Th><Th>SBOMs</Th><Th>Latest</Th><Th>Current</Th><Th>Schedule</Th><Th>Status</Th><Th className="text-right">Actions</Th></tr></TableHead><TableBody>{pagination.pageItems.length === 0 ? <EmptyRow cols={7} message="No matching applications. Adjust or clear your filters." /> : pagination.pageItems.map(product => <tr key={product.id}><Td className="min-w-[200px] max-w-sm"><Link href={`/products/${product.id}`} className="font-semibold text-hcl-navy hover:text-hcl-blue hover:underline">{product.name}</Link><p title={product.description || undefined} className="mt-1 line-clamp-2 text-xs leading-relaxed text-hcl-muted">{product.description || 'No description provided.'}</p></Td><Td>{product.sbom_count ?? 0}</Td><Td>{latest(product)}</Td><Td>{current(product)}</Td><Td><ProductScheduleStatus productId={product.id} /></Td><Td>{status(product)}</Td><Td><div className="flex justify-end">{applicationActions(product)}</div></Td></tr>)}</TableBody></Table></div>
          <div className="space-y-3 md:hidden">{pagination.pageItems.length === 0 && <p className="text-sm text-hcl-muted">No matching applications. Adjust or clear your filters.</p>}{pagination.pageItems.map(product => <article key={product.id} aria-label={product.name} className="min-w-0 rounded-lg border border-border p-3"><div className="flex items-start justify-between gap-2"><Link href={`/products/${product.id}`} className="min-w-0 break-words text-sm font-semibold text-hcl-navy">{product.name}</Link>{status(product)}</div><p className="mt-2 break-words text-xs text-hcl-muted">{product.description || 'No description provided.'}</p><dl className="mt-3 grid grid-cols-2 gap-3 text-xs"><div><dt className="text-hcl-muted">SBOMs</dt><dd>{product.sbom_count ?? 0}</dd></div><div><dt className="text-hcl-muted">Current</dt><dd>{current(product)}</dd></div><div><dt className="text-hcl-muted">Latest</dt><dd>{latest(product)}</dd></div><div><dt className="text-hcl-muted">Schedule</dt><dd><ProductScheduleStatus productId={product.id} /></dd></div></dl><div className="mt-3 flex items-center justify-between"><Link href={`/products/${product.id}`} className="text-sm font-medium text-hcl-blue">View application</Link>{applicationActions(product)}</div></article>)}</div>
          {(search || statusFilter !== 'all') && <Button size="sm" variant="ghost" className="mt-3" onClick={() => { changeSearch(''); changeStatus('all'); }}>Clear application filters</Button>}
          {pagination.totalPages > 1 && <Pagination page={pagination.page} pageSize={pagination.pageSize} total={pagination.total} totalPages={pagination.totalPages} rangeStart={pagination.rangeStart} rangeEnd={pagination.rangeEnd} hasPrev={pagination.hasPrev} hasNext={pagination.hasNext} onPageChange={pagination.setPage} onPageSizeChange={pagination.setPageSize} itemNoun="application" />}
        </>}
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

