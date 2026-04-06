'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Eye, Trash2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { deleteSbom } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type { SBOMSource } from '@/types';

interface SbomsTableProps {
  sboms: SBOMSource[] | undefined;
  isLoading: boolean;
  error: Error | null;
}

export function SbomsTable({ sboms, isLoading, error }: SbomsTableProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [deleteTarget, setDeleteTarget] = useState<SBOMSource | null>(null);

  const deleteMutation = useMutation({
    // Pass created_by as user_id; backend allows delete when created_by is null
    mutationFn: (sbom: SBOMSource) => deleteSbom(sbom.id, sbom.created_by ?? ''),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sboms'] });
      showToast('SBOM deleted successfully', 'success');
      setDeleteTarget(null);
    },
    onError: (err: Error) => {
      showToast(`Delete failed: ${err.message}`, 'error');
    },
  });

  if (error) {
    return (
      <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load SBOMs: {error.message}
      </div>
    );
  }

  return (
    <>
      <div className="bg-white rounded-xl border border-hcl-border shadow-card overflow-hidden">
        <Table>
          <TableHead>
            <tr>
              <Th>ID</Th>
              <Th>Name</Th>
              <Th>Project</Th>
              <Th>Version</Th>
              <Th>Format</Th>
              <Th>Created By</Th>
              <Th>Created On</Th>
              <Th className="text-right">Actions</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={8} />)
            ) : !sboms?.length ? (
              <EmptyRow cols={8} message="No SBOMs found. Upload your first SBOM!" />
            ) : (
              sboms.map((sbom) => (
                <tr key={sbom.id} className="hover:bg-hcl-light/40 transition-colors">
                  <Td className="font-mono text-xs text-hcl-muted">#{sbom.id}</Td>
                  <Td className="font-medium text-hcl-navy max-w-[200px] truncate">
                    {sbom.sbom_name}
                  </Td>
                  <Td className="text-hcl-muted">{sbom.project_name || (sbom.projectid ? `#${sbom.projectid}` : '—')}</Td>
                  <Td className="text-hcl-muted">{sbom.sbom_version || sbom.productver || '—'}</Td>
                  <Td className="text-hcl-muted">{sbom.sbom_type || '—'}</Td>
                  <Td className="text-hcl-muted">{sbom.created_by || '—'}</Td>
                  <Td className="text-hcl-muted whitespace-nowrap">{formatDate(sbom.created_on)}</Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => router.push(`/sboms/${sbom.id}`)}
                        className="p-1.5 text-hcl-muted hover:text-hcl-blue hover:bg-hcl-light rounded-lg transition-colors"
                        aria-label="View SBOM"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(sbom)}
                        className="p-1.5 text-hcl-muted hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        aria-label="Delete SBOM"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
        title="Delete SBOM"
        message={`Are you sure you want to delete "${deleteTarget?.sbom_name}"? This action cannot be undone.`}
        confirmLabel="Delete SBOM"
        loading={deleteMutation.isPending}
      />
    </>
  );
}
