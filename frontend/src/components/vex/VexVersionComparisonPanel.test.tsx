// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { VexVersionComparisonPanel } from './VexVersionComparisonPanel';
const api = vi.hoisted(() => ({getVexVersionComparison: vi.fn()}));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/useAuth', () => ({useAuth: () => ({activeTenantId: '1'})}));
vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({CveDetailDialog: ({scanId,componentId}: {scanId:number;componentId:number}) => <div>Details run {scanId} component {componentId}</div>}));
const data = {previous_version:'1',current_version:'2',previous_run_id:10,current_run_id:20,
  previous_findings:81,current_findings:15,still_detected:12,new:3,no_longer_observed:69,unresolved_comparison:0,limitations:[],
  items:[{category:'NO_LONGER_OBSERVED',reason:'Reason not determined.',previous:{vulnerability_id:'CVE-2026-1001',component_id:4,component_name:'library',component_version:'1',sbom_id:1,analysis_run_id:10},current:null},
  {category:'NEW',reason:'Reason not determined.',previous:null,current:{vulnerability_id:'CVE-2026-2001',component_id:8,component_name:'library',component_version:'2',sbom_id:2,analysis_run_id:20}}]};
function show() { return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><VexVersionComparisonPanel sbomId={2}/></QueryClientProvider>); }
beforeEach(() => {vi.clearAllMocks();api.getVexVersionComparison.mockResolvedValue(data);});
it('compares actual distinct contexts, preserves versions, and never asserts Fixed',async () => {
  show();expect(api.getVexVersionComparison).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Compare versions'}));
  expect(await screen.findByText('Previous: 1 → Current: 2')).toBeInTheDocument();expect(screen.getByText('81')).toBeInTheDocument();
  expect(screen.getByText(/No longer observed does not mean Fixed/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Comparison category'),{target:{value:'NO_LONGER_OBSERVED'}});
  expect(screen.queryByText(/CVE-2026-2001/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Open previous details'}));expect(screen.getByText('Details run 10 component 4')).toBeInTheDocument();
  expect(screen.getByRole('link',{name:'View previous investigations'})).toHaveAttribute('href','/vex-investigation?version_scope=all&sbom_id=1&q=CVE-2026-1001');
});
it('shows loading without premature comparison counts',async () => {
  api.getVexVersionComparison.mockReturnValue(new Promise(()=>{}));show();fireEvent.click(screen.getByRole('button',{name:'Compare versions'}));
  expect(await screen.findByRole('status')).toHaveTextContent('Loading version comparison');expect(screen.queryByText('81')).not.toBeInTheDocument();
});
it('shows unavailable analysis error without misleading zero counts',async () => {
  api.getVexVersionComparison.mockRejectedValue(new Error('not ready'));show();fireEvent.click(screen.getByRole('button',{name:'Compare versions'}));
  expect(await screen.findByText(/Both versions require successful analyses/)).toBeInTheDocument();expect(screen.queryByText('Previous findings')).not.toBeInTheDocument();
});
it('shows uncertainty and has responsive theme-aware surfaces',async () => {
  api.getVexVersionComparison.mockResolvedValue({...data,limitations:['Source coverage differs.'],unresolved_comparison:69,no_longer_observed:0});
  show();fireEvent.click(screen.getByRole('button',{name:'Compare versions'}));expect(await screen.findByText('Source coverage differs.')).toBeInTheDocument();
  expect(screen.getByRole('region',{name:'Version comparison'})).toHaveClass('bg-surface');
  await waitFor(()=>expect(api.getVexVersionComparison).toHaveBeenCalledWith(2,expect.any(AbortSignal)));
});
