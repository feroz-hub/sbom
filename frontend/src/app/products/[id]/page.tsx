'use client';

import Link from 'next/link';
import { use, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, Play, Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { PageSpinner } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { SbomStatusBadge } from '@/components/sboms/SbomStatusBadge';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { getProduct, getProductSboms } from '@/lib/api';
import { invalidateProductSurfaces } from '@/lib/queryInvalidation';
import { formatDate } from '@/lib/utils';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { SBOMSource } from '@/types';

/**
 * One SBOM row, owning its own analysis stream so Run Analysis works here the
 * same way it does on the SBOM detail screen. The hook stays inert until
 * `startAnalysis` is called, so an idle row costs nothing.
 */
function ProductSbomRow({ sbom }: { sbom: SBOMSource }) {
  const { state, startAnalysis } = useAnalysisStream(sbom.id);
  const isAnalyzing =
    state.phase === 'connecting' || state.phase === 'parsing' || state.phase === 'running';

  // While the stream is live the server has not refreshed `latest_analysis`
  // yet — drive the badge off the stream phase until the refetch lands.
  const optimisticStatus: AnalysisStatus | undefined = isAnalyzing
    ? 'RUNNING'
    : state.phase === 'error'
      ? 'ERROR'
      : undefined;

  return (
    <tr>
      <Td className="font-mono text-xs text-hcl-muted">#{sbom.id}</Td>
      <Td>
        <Link
          href={`/sboms/${sbom.id}`}
          className="font-medium text-hcl-navy hover:text-hcl-blue hover:underline"
        >
          {sbom.sbom_name}
        </Link>
      </Td>
      <Td className="text-hcl-muted">{sbom.sbom_version || sbom.productver || '—'}</Td>
      <Td>
        <SbomStatusBadge
          sbomId={sbom.id}
          latestAnalysis={sbom.latest_analysis}
          initialStatus={optimisticStatus}
          initialFindings={state.summary?.total}
        />
      </Td>
      <Td className="text-hcl-muted">{sbom.created_by || '—'}</Td>
      <Td className="text-hcl-muted">{formatDate(sbom.created_on)}</Td>
      <Td className="text-right">
        <div className="flex items-center justify-end gap-2">
          <Link
            href={`/sboms/${sbom.id}`}
            className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-row-hover hover:text-hcl-blue"
            aria-label={`View ${sbom.sbom_name}`}
          >
            <Eye className="h-4 w-4" />
            View SBOM
          </Link>
          <Button
            onClick={() => startAnalysis({ sources: ['NVD', 'OSV', 'GITHUB'] })}
            loading={isAnalyzing}
            disabled={isAnalyzing}
            size="sm"
          >
            <Play className="h-4 w-4" />
            {isAnalyzing ? 'Analyzing…' : 'Run Analysis'}
          </Button>
        </div>
      </Td>
    </tr>
  );
}

interface ProductDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function ProductDetailPage({ params }: ProductDetailPageProps) {
  const { id: idParam } = use(params);
  const id = Number(idParam);
  const queryClient = useQueryClient();
  const [showUpload, setShowUpload] = useState(false);

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
      <TopBar
        title={product.name}
        breadcrumbs={[{ label: 'Projects', href: '/projects' }]}
        action={
          <Button onClick={() => setShowUpload(true)}>
            <Upload className="h-4 w-4" />
            Upload SBOM
          </Button>
        }
      />
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
                  <Th>Analysis</Th>
                  <Th>Created By</Th>
                  <Th>Created On</Th>
                  <Th className="text-right">Actions</Th>
                </tr>
              </TableHead>
              <TableBody>
                {sbomsQuery.isLoading ? (
                  <EmptyRow cols={7} message="Loading SBOMs..." />
                ) : sboms.length === 0 ? (
                  <EmptyRow cols={7} message="No SBOMs are linked to this product yet." />
                ) : (
                  sboms.map((sbom) => <ProductSbomRow key={sbom.id} sbom={sbom} />)
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
      <SbomUploadModal
        open={showUpload}
        onClose={() => setShowUpload(false)}
        initialProjectId={product.project_id}
        initialProductId={product.id}
        onSuccess={() => {
          invalidateProductSurfaces(queryClient, id);
        }}
      />
    </div>
  );
}
