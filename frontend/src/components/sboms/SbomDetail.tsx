'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Play, ArrowLeft, ExternalLink } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge } from '@/components/ui/Badge';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { PageSpinner, SkeletonRow } from '@/components/ui/Spinner';
import { getSbomComponents, analyzeSbom, getRuns } from '@/lib/api';
import { formatDate, formatDuration } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type { SBOMSource } from '@/types';

interface SbomDetailProps {
  sbom: SBOMSource;
}

export function SbomDetail({ sbom }: SbomDetailProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [analyzing, setAnalyzing] = useState(false);

  const { data: components, isLoading: compLoading } = useQuery({
    queryKey: ['sbom-components', sbom.id],
    queryFn: ({ signal }) => getSbomComponents(sbom.id, signal),
  });

  const { data: runs, isLoading: runsLoading } = useQuery({
    queryKey: ['runs', { sbom_id: sbom.id }],
    queryFn: ({ signal }) => getRuns({ sbom_id: sbom.id }, signal),
  });

  const analyzeMutation = useMutation({
    mutationFn: () => analyzeSbom(sbom.id),
    onMutate: () => setAnalyzing(true),
    onSuccess: (run) => {
      queryClient.invalidateQueries({ queryKey: ['runs'] });
      showToast('Analysis started successfully', 'success');
      setAnalyzing(false);
      if (run?.id) {
        router.push(`/analysis/${run.id}`);
      }
    },
    onError: (err: Error) => {
      showToast(`Analysis failed: ${err.message}`, 'error');
      setAnalyzing(false);
    },
  });

  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-800 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" /> Back to SBOMs
      </button>

      {/* SBOM Metadata Card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>SBOM Details</CardTitle>
          <Button
            onClick={() => analyzeMutation.mutate()}
            loading={analyzing}
            size="sm"
          >
            <Play className="h-4 w-4" />
            Run Analysis
          </Button>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Name', value: sbom.sbom_name },
              { label: 'Format / Type', value: sbom.sbom_type || '—' },
              { label: 'SBOM Version', value: sbom.sbom_version || '—' },
              { label: 'Product Version', value: sbom.productver || '—' },
              { label: 'Project ID', value: sbom.projectid ? `#${sbom.projectid}` : '—' },
              { label: 'Created By', value: sbom.created_by || '—' },
              { label: 'Created On', value: formatDate(sbom.created_on) },
              { label: 'Updated On', value: formatDate(sbom.updated_on) },
            ].map(({ label, value }) => (
              <div key={label}>
                <dt className="text-xs font-medium text-gray-400 uppercase tracking-wide">{label}</dt>
                <dd className="mt-1 text-sm font-medium text-gray-900 break-words">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>

      {/* Components Table */}
      <Card>
        <CardHeader>
          <CardTitle>
            Components{' '}
            {components && (
              <span className="ml-2 text-sm font-normal text-gray-400">
                ({components.length})
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <div className="overflow-hidden">
          <Table>
            <TableHead>
              <tr>
                <Th>Name</Th>
                <Th>Version</Th>
                <Th>Type</Th>
                <Th>CPE</Th>
                <Th>PURL</Th>
              </tr>
            </TableHead>
            <TableBody>
              {compLoading ? (
                Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={5} />)
              ) : !components?.length ? (
                <EmptyRow cols={5} message="No components found for this SBOM" />
              ) : (
                components.map((c) => (
                  <tr key={c.id} className="hover:bg-gray-50">
                    <Td className="font-medium text-gray-900">{c.name}</Td>
                    <Td className="font-mono text-xs">{c.version || '—'}</Td>
                    <Td className="text-gray-500">{c.component_type || '—'}</Td>
                    <Td className="font-mono text-xs text-gray-500 max-w-[180px] truncate">
                      {c.cpe || '—'}
                    </Td>
                    <Td className="font-mono text-xs text-gray-500 max-w-[200px] truncate">
                      {c.purl || '—'}
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </Card>

      {/* Analysis Runs */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Runs</CardTitle>
        </CardHeader>
        <div className="overflow-hidden">
          <Table>
            <TableHead>
              <tr>
                <Th>Run ID</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Duration</Th>
                <Th>Started On</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </TableHead>
            <TableBody>
              {runsLoading ? (
                Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
              ) : !runs?.length ? (
                <EmptyRow cols={6} message="No analysis runs yet. Click 'Run Analysis' to get started." />
              ) : (
                runs.map((run) => (
                  <tr key={run.id} className="hover:bg-gray-50">
                    <Td className="font-mono text-xs text-gray-400">#{run.id}</Td>
                    <Td>
                      <StatusBadge status={run.run_status} />
                    </Td>
                    <Td className="text-gray-700">{run.total_findings ?? '—'}</Td>
                    <Td className="text-gray-500">{formatDuration(run.duration_seconds)}</Td>
                    <Td className="text-gray-500 whitespace-nowrap">{formatDate(run.started_on)}</Td>
                    <Td className="text-right">
                      <Link
                        href={`/analysis/${run.id}`}
                        className="inline-flex items-center gap-1 text-xs text-primary hover:underline font-medium"
                      >
                        View <ExternalLink className="h-3 w-3" />
                      </Link>
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </Card>
    </div>
  );
}
