'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FindingsTrendChart } from './FindingsTrendChart/FindingsTrendChart';
import { getDashboardTrend, type DashboardFilterScope } from '@/lib/api';
import type { DashboardTrend } from '@/types';

export function PortfolioTrend({ initial, scope, tenantId }: { initial?: DashboardTrend; scope: DashboardFilterScope; tenantId?: string | null }) {
  const [days, setDays] = useState(30);
  const query = useQuery({
    queryKey: ['portfolio-trend', tenantId, scope.projectId, scope.applicationId, scope.sbomId, days],
    queryFn: ({ signal }) => getDashboardTrend(days, signal, scope),
    enabled: !!tenantId && days !== 30,
    retry: 1,
  });
  return <div className="min-w-0 rounded-xl border border-border bg-surface">
    <div className="flex items-center justify-between gap-3 border-b border-border-subtle px-5 py-2">
      <label htmlFor="portfolio-trend-period" className="text-xs text-hcl-muted">Observation window</label>
      <select id="portfolio-trend-period" value={days} onChange={e => setDays(Number(e.target.value))} className="rounded border border-border bg-surface px-2 py-1 text-xs text-hcl-navy focus-visible:ring-2 focus-visible:ring-hcl-blue">
        {[7, 30, 90].map(n => <option key={n} value={n}>Last {n} days</option>)}
      </select>
    </div>
    {days !== 30 && query.isError ? <p role="alert" className="p-5 text-sm text-hcl-muted">Trend data unavailable. <button onClick={() => void query.refetch()} className="rounded text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">Retry</button></p> : <FindingsTrendChart compact data={days === 30 ? initial : query.data} isLoading={days !== 30 && query.isPending} />}
  </div>;
}
