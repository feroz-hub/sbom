'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Select } from '@/components/ui/Select';
import { RunsTable } from '@/components/analysis/RunsTable';
import { getRuns, getProjects, getSboms } from '@/lib/api';

export default function AnalysisPage() {
  const [projectFilter, setProjectFilter] = useState('');
  const [sbomFilter, setSbomFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const { data: sboms } = useQuery({
    queryKey: ['sboms'],
    queryFn: ({ signal }) => getSboms(1, 100, signal),
  });

  const { data: runs, isLoading, error } = useQuery({
    queryKey: ['runs', { projectFilter, sbomFilter, statusFilter }],
    queryFn: ({ signal }) =>
      getRuns(
        {
          project_id: projectFilter ? Number(projectFilter) : undefined,
          sbom_id: sbomFilter ? Number(sbomFilter) : undefined,
          run_status: statusFilter || undefined,
          page: 1,
          page_size: 50,
        },
        signal
      ),
  });

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Analysis Runs" />
      <div className="p-6 space-y-4">
        {/* Filters */}
        <div className="flex flex-wrap gap-3 bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
          <Select
            value={projectFilter}
            onChange={(e) => setProjectFilter(e.target.value)}
            className="w-52"
            placeholder="All Projects"
          >
            {projects?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.project_name}
              </option>
            ))}
          </Select>

          <Select
            value={sbomFilter}
            onChange={(e) => setSbomFilter(e.target.value)}
            className="w-52"
            placeholder="All SBOMs"
          >
            {sboms?.map((s) => (
              <option key={s.id} value={s.id}>
                {s.sbom_name}
              </option>
            ))}
          </Select>

          <Select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-44"
            placeholder="All Statuses"
          >
            <option value="PASS">PASS</option>
            <option value="FAIL">FAIL</option>
            <option value="PARTIAL">PARTIAL</option>
            <option value="ERROR">ERROR</option>
            <option value="RUNNING">RUNNING</option>
            <option value="PENDING">PENDING</option>
          </Select>

          {(projectFilter || sbomFilter || statusFilter) && (
            <button
              onClick={() => {
                setProjectFilter('');
                setSbomFilter('');
                setStatusFilter('');
              }}
              className="text-sm text-gray-500 hover:text-gray-800 underline"
            >
              Clear filters
            </button>
          )}
        </div>

        <RunsTable runs={runs} isLoading={isLoading} error={error} />
      </div>
    </div>
  );
}
