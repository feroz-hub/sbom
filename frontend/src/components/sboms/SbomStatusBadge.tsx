'use client';

import { useState, useEffect } from 'react';
import { Loader2 } from 'lucide-react';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';

interface SbomStatusBadgeProps {
  sbomId: number;
  initialStatus?: AnalysisStatus;
  initialFindings?: number;
}

const STATUS_STYLES: Record<AnalysisStatus, string> = {
  ANALYSING:    'bg-blue-50 text-blue-700 border-blue-200',
  PASS:         'bg-green-50 text-green-700 border-green-200',
  FAIL:         'bg-red-50 text-red-700 border-red-200',
  PARTIAL:      'bg-amber-50 text-amber-700 border-amber-200',
  ERROR:        'bg-red-50 text-red-600 border-red-200',
  NOT_ANALYSED: 'bg-slate-50 text-slate-500 border-slate-200',
};

const STATUS_LABELS: Record<AnalysisStatus, string> = {
  ANALYSING:    'Analysing…',
  PASS:         'Pass',
  FAIL:         'Fail',
  PARTIAL:      'Partial',
  ERROR:        'Failed',
  NOT_ANALYSED: '—',
};

export function SbomStatusBadge({ sbomId, initialStatus, initialFindings }: SbomStatusBadgeProps) {
  const [status, setStatus] = useState<AnalysisStatus>(initialStatus ?? 'NOT_ANALYSED');
  const [findings, setFindings] = useState<number | undefined>(initialFindings);

  // Keep in sync with initialStatus prop changes (e.g., optimistic update from parent)
  useEffect(() => {
    if (initialStatus) setStatus(initialStatus);
  }, [initialStatus]);

  // Subscribe to global analysis status events
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ sbomId: number; status: AnalysisStatus; findingsCount?: number }>).detail;
      if (detail.sbomId === sbomId) {
        setStatus(detail.status);
        if (detail.findingsCount !== undefined) setFindings(detail.findingsCount);
      }
    };
    window.addEventListener('sbom-analysis-update', handler);
    return () => window.removeEventListener('sbom-analysis-update', handler);
  }, [sbomId]);

  if (status === 'NOT_ANALYSED') {
    return <span className="text-xs text-slate-400">—</span>;
  }

  const styles = STATUS_STYLES[status];
  const label = STATUS_LABELS[status];

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${styles}`}
    >
      {status === 'ANALYSING' && <Loader2 className="h-3 w-3 animate-spin" />}
      {label}
      {status !== 'ANALYSING' && findings !== undefined && findings > 0 && (
        <span className="font-bold">{findings}</span>
      )}
    </span>
  );
}
