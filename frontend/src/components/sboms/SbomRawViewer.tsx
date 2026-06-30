'use client';

import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useMemo, useState } from 'react';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Pagination } from '@/components/ui/Pagination';
import { PageSpinner } from '@/components/ui/Spinner';
import { BASE_URL, downloadSbomOriginal, getSbomRawChunk } from '@/lib/api';
import type { SbomDocumentStats } from '@/types';

const RAW_PAGE_SIZE = 100;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface SbomRawViewerProps {
  sbomId: number;
  stats?: SbomDocumentStats | null;
  workspaceAction?: ReactNode;
  workspaceUnavailableReason?: string | null;
}

export function SbomRawViewer({ sbomId, stats, workspaceAction, workspaceUnavailableReason }: SbomRawViewerProps) {
  const [page, setPage] = useState(1);
  const offset = (page - 1) * RAW_PAGE_SIZE;

  const { data, isLoading, isError } = useQuery({
    queryKey: ['sbom-raw', sbomId, offset, RAW_PAGE_SIZE],
    queryFn: ({ signal }) => getSbomRawChunk(sbomId, offset, RAW_PAGE_SIZE, signal),
  });

  const totalLines = data?.total_lines ?? stats?.line_count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalLines / RAW_PAGE_SIZE));
  const rangeStart = totalLines === 0 ? 0 : offset + 1;
  const rangeEnd = totalLines === 0 ? 0 : Math.min(offset + RAW_PAGE_SIZE, totalLines);

  const previewLabel = useMemo(() => {
    if (!totalLines) return 'No stored document lines.';
    if (totalLines <= RAW_PAGE_SIZE) {
      return `Showing all ${totalLines.toLocaleString()} lines.`;
    }
    return `Preview: lines ${rangeStart.toLocaleString()}-${rangeEnd.toLocaleString()} of ${totalLines.toLocaleString()}.`;
  }, [rangeEnd, rangeStart, totalLines]);

  const handleDownload = async () => {
    const blob = await downloadSbomOriginal(sbomId);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `sbom-${sbomId}`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div>
          <CardTitle>SBOM Document</CardTitle>
          <p className="mt-1 text-xs text-hcl-muted">
            {stats
              ? `${formatBytes(stats.file_size_bytes)} · ${stats.line_count.toLocaleString()} lines · ${stats.component_count.toLocaleString()} components stored`
              : 'Paginated raw document viewer'}
          </p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void handleDownload()}>
            <Download className="h-3.5 w-3.5" /> Download original
          </Button>
          {workspaceAction}
          <a
            href={`${BASE_URL}/api/sboms/${sbomId}/download`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-hcl-border px-3 py-1.5 text-xs font-semibold text-hcl-navy hover:bg-hcl-light"
            download
          >
            Direct link
          </a>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {workspaceUnavailableReason ? (
          <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            {workspaceUnavailableReason}
          </p>
        ) : null}
        <p className="text-xs font-medium text-hcl-muted">{previewLabel}</p>
        {isLoading ? (
          <PageSpinner />
        ) : isError ? (
          <p className="text-sm text-red-600">Could not load raw SBOM preview.</p>
        ) : (
          <pre className="max-h-[420px] overflow-auto rounded-lg border border-hcl-border bg-hcl-light/40 p-3 font-mono text-[11px] leading-5 text-hcl-navy">
            {(data?.lines ?? []).map((line, index) => (
              <div key={`${offset + index}-${line.slice(0, 12)}`}>
                <span className="mr-3 inline-block w-12 text-right text-hcl-muted">{offset + index + 1}</span>
                {line}
              </div>
            ))}
          </pre>
        )}
        {totalLines > RAW_PAGE_SIZE ? (
          <Pagination
            page={page}
            pageSize={RAW_PAGE_SIZE}
            total={totalLines}
            totalPages={totalPages}
            rangeStart={rangeStart}
            rangeEnd={rangeEnd}
            hasPrev={page > 1}
            hasNext={page < totalPages}
            onPageChange={setPage}
            onPageSizeChange={() => {}}
            pageSizeOptions={[RAW_PAGE_SIZE]}
            itemNoun="line"
          />
        ) : null}
      </CardContent>
    </Card>
  );
}
