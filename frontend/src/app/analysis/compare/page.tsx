'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, GitCompareArrows, Minus, Plus } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { PageSpinner } from '@/components/ui/Spinner';
import { compareRuns } from '@/lib/api';
import { formatDate } from '@/lib/utils';

function parseRunId(value: string | null): number | null {
  if (!value) return null;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export default function CompareRunsPage() {
  const params = useSearchParams();
  const router = useRouter();

  const runA = parseRunId(params.get('run_a'));
  const runB = parseRunId(params.get('run_b'));
  const canQuery = runA !== null && runB !== null && runA !== runB;

  const { data, isLoading, error } = useQuery({
    queryKey: ['compare-runs', runA, runB],
    queryFn: ({ signal }) => compareRuns(runA as number, runB as number, signal),
    enabled: canQuery,
  });

  const severityRows = useMemo(() => {
    if (!data) return [];
    const d = data.severity_delta;
    return [
      { label: 'Critical', delta: d.critical, color: 'text-red-700' },
      { label: 'High', delta: d.high, color: 'text-orange-700' },
      { label: 'Medium', delta: d.medium, color: 'text-amber-700' },
      { label: 'Low', delta: d.low, color: 'text-hcl-blue' },
    ];
  }, [data]);

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Compare Analysis Runs" />
      <div className="p-6 space-y-6">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm text-hcl-muted hover:text-hcl-navy transition-colors"
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </button>

        {!canQuery && (
          <Card>
            <CardContent>
              <div className="py-8 text-center text-sm text-hcl-muted">
                <GitCompareArrows className="h-8 w-8 mx-auto mb-3 text-hcl-muted" />
                <p className="font-medium text-hcl-navy mb-1">No runs selected</p>
                <p>
                  Open this page with{' '}
                  <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">
                    ?run_a=&lt;id&gt;&amp;run_b=&lt;id&gt;
                  </code>
                  , or select exactly two runs on the{' '}
                  <Link href="/analysis" className="text-hcl-blue hover:underline">
                    Analysis Runs
                  </Link>{' '}
                  page and click <span className="font-medium">Compare</span>.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {canQuery && isLoading && (
          <div className="py-12">
            <PageSpinner />
          </div>
        )}

        {canQuery && error && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            Failed to compare runs: {(error as Error).message}
          </div>
        )}

        {canQuery && data && (
          <>
            {/* Run headers */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { label: 'Run A', run: data.run_a },
                { label: 'Run B', run: data.run_b },
              ].map(({ label, run }) => (
                <Card key={label}>
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <span>
                        {label} —{' '}
                        <Link
                          href={`/analysis/${run.id}`}
                          className="font-mono text-hcl-blue hover:underline"
                        >
                          #{run.id}
                        </Link>
                      </span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <dl className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <dt className="text-hcl-muted">SBOM</dt>
                        <dd className="font-medium text-hcl-navy">
                          {run.sbom_name || '—'}
                        </dd>
                      </div>
                      <div className="flex justify-between">
                        <dt className="text-hcl-muted">Completed</dt>
                        <dd className="font-medium text-hcl-navy">
                          {formatDate(run.completed_on)}
                        </dd>
                      </div>
                    </dl>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Summary counts */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <SummaryTile
                label="New findings"
                count={data.new_findings.length}
                icon={<Plus className="h-4 w-4" />}
                tone="negative"
              />
              <SummaryTile
                label="Resolved findings"
                count={data.resolved_findings.length}
                icon={<Minus className="h-4 w-4" />}
                tone="positive"
              />
              <SummaryTile
                label="Common findings"
                count={data.common_findings.length}
                icon={<GitCompareArrows className="h-4 w-4" />}
                tone="neutral"
              />
            </div>

            {/* Severity delta */}
            <Card>
              <CardHeader>
                <CardTitle>Severity Delta (B − A)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {severityRows.map(({ label, delta, color }) => (
                    <div key={label} className="text-center">
                      <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">
                        {label}
                      </dt>
                      <dd className={`mt-1 text-2xl font-semibold ${color}`}>
                        {delta > 0 ? `+${delta}` : delta}
                      </dd>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Finding lists */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <FindingsList
                title="New in Run B"
                items={data.new_findings}
                emptyMsg="No new findings."
                accent="text-red-700"
              />
              <FindingsList
                title="Resolved in Run B"
                items={data.resolved_findings}
                emptyMsg="Nothing was resolved."
                accent="text-green-700"
              />
              <FindingsList
                title="Common"
                items={data.common_findings}
                emptyMsg="No overlap."
                accent="text-slate-700"
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function SummaryTile({
  label,
  count,
  icon,
  tone,
}: {
  label: string;
  count: number;
  icon: React.ReactNode;
  tone: 'positive' | 'negative' | 'neutral';
}) {
  const toneClass =
    tone === 'negative'
      ? 'bg-red-50 border-red-200 text-red-700'
      : tone === 'positive'
        ? 'bg-green-50 border-green-200 text-green-700'
        : 'bg-slate-50 border-slate-200 text-slate-700';
  return (
    <Card>
      <CardContent>
        <div className={`inline-flex items-center gap-2 px-2 py-1 rounded border ${toneClass}`}>
          {icon}
          <span className="text-xs font-medium uppercase tracking-wide">{label}</span>
        </div>
        <p className="mt-3 text-3xl font-semibold text-hcl-navy">{count}</p>
      </CardContent>
    </Card>
  );
}

function FindingsList({
  title,
  items,
  emptyMsg,
  accent,
}: {
  title: string;
  items: string[];
  emptyMsg: string;
  accent: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className={`text-sm ${accent}`}>
          {title}
          <span className="ml-2 text-xs font-normal text-hcl-muted">({items.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 pb-4 px-4">
        {items.length === 0 ? (
          <p className="text-sm text-hcl-muted py-4">{emptyMsg}</p>
        ) : (
          <ul className="max-h-80 overflow-y-auto text-xs font-mono space-y-1">
            {items.map((id) => (
              <li
                key={id}
                className="px-2 py-1 rounded hover:bg-hcl-light/40 text-hcl-navy truncate"
                title={id}
              >
                {id}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
