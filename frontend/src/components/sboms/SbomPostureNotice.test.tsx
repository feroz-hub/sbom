// @vitest-environment jsdom
import {fireEvent,render,screen} from '@testing-library/react';
import {beforeEach,expect,it,vi} from 'vitest';
import {PostureEvidence,SbomPostureNotice} from './SbomPostureNotice';
import type {SbomPosture} from '@/types';
const item: SbomPosture={target_sbom_id:2,posture_sbom_id:1,product_id:1,
  current_sbom:{id:2,name:'TestApp',version:'A1.1.0'},latest_uploaded:{id:2,name:'TestApp',version:'A1.1.0'},
  latest_analyzed:{id:1,name:'TestApp',version:'A1.0.0'},posture_sbom:{id:1,name:'TestApp',version:'A1.0.0'},
  analysis_run_id:10,analysis_status:'ANALYSIS_PENDING',analysis_finding_rows:81,last_known_posture:true,
  coverage_incomplete:false,designation_required:false,warning:'The newer SBOM has not completed analysis. Showing the last known security posture from A1.0.0.'};
it('labels pending target and 81 last-known records from the correct version',()=>{
  render(<PostureEvidence items={[item]}/>);expect(screen.getByText(/Current SBOM: A1.1.0/)).toBeInTheDocument();
  expect(screen.getByText(/Last known posture: A1.0.0/)).toBeInTheDocument();expect(screen.getByText(/81 finding records/)).toBeInTheDocument();
  expect(screen.getByText(/newer SBOM has not completed analysis/)).toBeInTheDocument();
});
it('removes last-known warning once the new version supplies posture',()=>{
  render(<PostureEvidence items={[{...item,posture_sbom:item.current_sbom,last_known_posture:false,warning:null,analysis_status:'ANALYZED',analysis_finding_rows:15}]}/>);
  expect(screen.getByText(/Security posture: A1.1.0/)).toBeInTheDocument();expect(screen.queryByText(/newer SBOM/)).not.toBeInTheDocument();
});
it('does not call absent analysis zero risk',()=>{
  render(<PostureEvidence items={[{...item,analysis_run_id:null,analysis_finding_rows:null,warning:'No successful posture is available; empty counts do not establish zero risk.'}]}/>);
  expect(screen.getByText(/No successful analysis/)).toBeInTheDocument();expect(screen.queryByText(/0 finding records/)).not.toBeInTheDocument();
});

import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {getDashboardPostureVersions} from '@/lib/api';
vi.mock('@/hooks/useAuth',()=>({useAuth:()=>({activeTenantId:'1'})}));
vi.mock('@/lib/api',()=>({getDashboardPostureVersions:vi.fn()}));
const api=vi.mocked(getDashboardPostureVersions);
beforeEach(()=>vi.resetAllMocks());
function notice(initial?: {items:SbomPosture[]}){
 const client=new QueryClient({defaultOptions:{queries:{gcTime:0,retry:false}}});
 if(initial)client.setQueryData(['sbom-posture','1',null,null,null],initial);
 return render(<QueryClientProvider client={client}><SbomPostureNotice scope={{projectId:null,applicationId:null,sbomId:null}}/></QueryClientProvider>);
}
it('shows two analyzed applications including genuine zero without missing-evidence warning',async()=>{
 api.mockResolvedValue({items:[{...item,application_name:'Pump',last_known_posture:false,warning:null,analysis_finding_rows:108},{...item,target_sbom_id:3,application_name:'Upload',analysis_run_id:11,last_known_posture:false,warning:null,analysis_finding_rows:0}]});
 notice();await screen.findByText('Upload');expect(screen.getByText(/108 finding records/)).toBeInTheDocument();expect(screen.getByText(/0 finding records/)).toBeInTheDocument();expect(screen.queryByText(/unavailable|Partial posture/)).not.toBeInTheDocument();
});
it('identifies only missing lineages while preserving analyzed findings',()=>{
 render(<PostureEvidence items={[{...item,application_name:'Pump',warning:null},{...item,target_sbom_id:3,application_name:'Pending App',analysis_run_id:null,analysis_finding_rows:null,warning:null}]}/>);
 expect(screen.getByText(/Partial posture availability: 1 of 2/)).toHaveTextContent('Affected: Pending App');expect(screen.getByText(/81 finding records/)).toBeInTheDocument();
});
it('keeps provider coverage warning separate from evidence availability',()=>{
 render(<PostureEvidence items={[{...item,last_known_posture:false,coverage_incomplete:true,warning:'Analysis coverage incomplete: GITHUB unavailable.'}]}/>);
 expect(screen.getByText(/Analysis coverage incomplete/)).toBeInTheDocument();expect(screen.queryByText(/Partial posture availability/)).not.toBeInTheDocument();
});
it('shows loading without declaring missing evidence',()=>{
 api.mockImplementation(()=>new Promise(()=>{}));notice();expect(screen.getByText(/Loading version posture/)).toBeInTheDocument();expect(screen.queryByText(/unavailable/)).not.toBeInTheDocument();
});
it('shows retryable HTTP 500 separately from counts and recovers',async()=>{
 api.mockRejectedValue(Object.assign(new Error('server failed'),{status:500}));notice();
 await screen.findByText(/Version posture request failed.*HTTP 500/,{}, {timeout:4000});expect(screen.queryByText(/Empty counts/)).not.toBeInTheDocument();
 api.mockResolvedValue({items:[{...item,warning:null}]});fireEvent.click(screen.getByRole('button',{name:'Retry version posture'}));await screen.findByText(/81 finding records/);expect(screen.queryByText(/HTTP 500/)).not.toBeInTheDocument();
});
it('reports HTTP 403 as permission failure without automatic retry',async()=>{
 api.mockRejectedValue(Object.assign(new Error('forbidden'),{status:403}));notice();await screen.findByText(/permission.*HTTP 403/);expect(api).toHaveBeenCalledTimes(1);expect(screen.queryByText(/Empty counts/)).not.toBeInTheDocument();
});

it('retains labeled cached evidence when refresh fails',async()=>{
 api.mockRejectedValue(Object.assign(new Error('forbidden'),{status:403}));notice({items:[{...item,warning:null}]});
 await screen.findByText(/freshness could not be verified/);expect(screen.getByText(/81 finding records/)).toBeInTheDocument();
});
