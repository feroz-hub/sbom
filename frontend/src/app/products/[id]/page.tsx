'use client';

import Link from 'next/link';
import { use } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { PageSpinner } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { getProduct, getProductSboms } from '@/lib/api';
import { formatDate } from '@/lib/utils';

interface ProductDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function ProductDetailPage({ params }: ProductDetailPageProps) {
  const { id: idParam } = use(params);
  const id = Number(idParam);

  const productQuery = useQuery({
    queryKey: ['product', id],
    queryFn: ({ signal }) => getProduct(id, signal),
    enabled: Number.isFinite(id),
  });

  const sbomsQuery = useQuery({
    queryKey: ['product-sboms', id],
    queryFn: ({ signal }) => getProductSboms(id, signal),
    enabled: Number.isFinite(id),
  });

  if (productQuery.isLoading) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="Product" />
        <div className="p-6">
          <PageSpinner />
        </div>
      </div>
    );
  }

  if (productQuery.error || !productQuery.data) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="Product" breadcrumbs={[{ label: 'Projects', href: '/projects' }]} />
        <div className="p-6">
          <Alert variant="error" title={productQuery.error ? 'Could not load product' : 'Not found'}>
            {productQuery.error ? productQuery.error.message : 'This product does not exist or was removed.'}
          </Alert>
        </div>
      </div>
    );
  }

  const product = productQuery.data;
  const sboms = sbomsQuery.data ?? [];

  return (
    <div className="flex flex-col flex-1">
      <TopBar title={product.name} breadcrumbs={[{ label: 'Projects', href: '/projects' }]} />
      <div className="space-y-6 p-6">
        <Card>
          <CardHeader>
            <CardTitle>Product Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs font-medium uppercase text-hcl-muted">Project</dt>
                <dd className="mt-1 text-hcl-navy">Project #{product.project_id}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase text-hcl-muted">SBOMs</dt>
                <dd className="mt-1 text-hcl-navy">{product.sbom_count ?? sboms.length}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase text-hcl-muted">Latest Version</dt>
                <dd className="mt-1 text-hcl-navy">{product.latest_sbom_version || product.latest_version || '—'}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase text-hcl-muted">Status</dt>
                <dd className="mt-1 text-hcl-navy">{product.status || 'active'}</dd>
              </div>
              <div className="sm:col-span-2 lg:col-span-4">
                <dt className="text-xs font-medium uppercase text-hcl-muted">Description</dt>
                <dd className="mt-1 text-hcl-navy">{product.description || '—'}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>SBOMs</CardTitle>
          </CardHeader>
          <CardContent>
            <Table ariaLabel="Product SBOMs">
              <TableHead>
                <tr>
                  <Th>ID</Th>
                  <Th>Name</Th>
                  <Th>Version</Th>
                  <Th>Created By</Th>
                  <Th>Created On</Th>
                </tr>
              </TableHead>
              <TableBody>
                {sbomsQuery.isLoading ? (
                  <EmptyRow cols={5} message="Loading SBOMs..." />
                ) : sboms.length === 0 ? (
                  <EmptyRow cols={5} message="No SBOMs are linked to this product yet." />
                ) : (
                  sboms.map((sbom) => (
                    <tr key={sbom.id}>
                      <Td className="font-mono text-xs text-hcl-muted">#{sbom.id}</Td>
                      <Td>
                        <Link href={`/sboms/${sbom.id}`} className="font-medium text-hcl-navy hover:text-hcl-blue hover:underline">
                          {sbom.sbom_name}
                        </Link>
                      </Td>
                      <Td className="text-hcl-muted">{sbom.sbom_version || sbom.productver || '—'}</Td>
                      <Td className="text-hcl-muted">{sbom.created_by || '—'}</Td>
                      <Td className="text-hcl-muted">{formatDate(sbom.created_on)}</Td>
                    </tr>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
