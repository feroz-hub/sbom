// @vitest-environment jsdom
import {fireEvent,render,screen,within} from '@testing-library/react';
import {beforeEach,expect,it,vi} from 'vitest';
import {PostureEvidence,SbomPostureNotice} from './SbomPostureNotice';
import type {SbomPosture} from '@/types';
const item: SbomPosture={target_sbom_id:2,posture_sbom_id:1,product_id:1,
  current_sbom:{id:2,name:'TestApp',version:'A1.1.0'},latest_uploaded:{id:2,name:'TestApp',version:'A1.1.0'},
  latest_analyzed:{id:1,name:'TestApp',version:'A1.0.0'},posture_sbom:{id:1,name:'TestApp',version:'A1.0.0'},
  analysis_run_id:"00000000-0000-4000-8000-00000000000a",analysis_status:'ANALYSIS_PENDING',analysis_finding_rows:81,last_known_posture:true,
  coverage_incomplete:false,designation_required:false,warning:'The newer SBOM has not completed analysis. Showing the last known security posture from A1.0.0.'};
function expand(){fireEvent.click(screen.getByRole('button',{name:'Review version evidence'}));}
it('maps current, analyzed and last-known evidence separately__VEX_INV_002',()=>{
  render(<PostureEvidence items={[item]}/>);expand();
  const cells=screen.getAllByRole('cell');
  expect(cells[1]).toHaveTextContent('A1.1.0');expect(cells[3]).toHaveTextContent('A1.0.0');
  expect(cells[4]).toHaveTextContent('Evidence versionTestAppA1.0.0');expect(cells[4]).toHaveTextContent('Analysis finding rows: 81');
  expect(screen.getByRole('link',{name:`Open analysis run ${item.analysis_run_id}`})).toHaveAttribute('href',`/analysis/${item.analysis_run_id}`);
  expect(screen.getByText(/newer SBOM has not completed analysis/)).toBeInTheDocument();
});
it('removes last-known warning once the new version supplies posture',()=>{
  render(<PostureEvidence items={[{...item,posture_sbom:item.current_sbom,last_known_posture:false,warning:null,analysis_status:'ANALYZED',analysis_finding_rows:15}]}/>);
  expand();expect(screen.getByText('Analysis evidence available')).toBeInTheDocument();
  expect(screen.queryByText(/Security posture:/)).not.toBeInTheDocument();expect(screen.queryByText(/newer SBOM/)).not.toBeInTheDocument();
});
it('does not call absent analysis zero risk',()=>{
  render(<PostureEvidence items={[{...item,analysis_run_id:null,analysis_finding_rows:null,warning:'No successful posture is available; empty counts do not establish zero risk.'}]}/>);
  expand();expect(screen.getByText('No successful analysis')).toBeInTheDocument();expect(screen.queryByText(/Analysis finding rows:/)).not.toBeInTheDocument();
});

import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {getDashboardPostureVersions} from '@/lib/api';
const auth=vi.hoisted(()=>({activeTenantId:'1' as string|null}));
vi.mock('@/hooks/useAuth',()=>({useAuth:()=>auth}));
vi.mock('@/lib/api',()=>({getDashboardPostureVersions:vi.fn()}));
const api=vi.mocked(getDashboardPostureVersions);
beforeEach(()=>{vi.resetAllMocks();auth.activeTenantId='1';});
function notice(initial?: {items:SbomPosture[]}){
 const client=new QueryClient({defaultOptions:{queries:{gcTime:0,retry:false}}});
 if(initial)client.setQueryData(['sbom-posture','1',null,null,null],initial);
 return {...render(<QueryClientProvider client={client}><SbomPostureNotice scope={{projectId:null,applicationId:null,sbomId:null}}/></QueryClientProvider>),client};
}
it('shows two analyzed applications including genuine zero without missing-evidence warning',async()=>{
 api.mockResolvedValue({items:[{...item,application_name:'Pump',last_known_posture:false,warning:null,analysis_finding_rows:108},{...item,target_sbom_id:3,application_name:'Upload',analysis_run_id:"00000000-0000-4000-8000-00000000000b",last_known_posture:false,warning:null,analysis_finding_rows:0}]});
 notice();await screen.findByRole('button',{name:'Review version evidence'});expand();
 expect(within(screen.getByText('Pump').closest('tr')!).getByText(/Analysis finding rows:/)).toHaveTextContent('108');
 expect(within(screen.getByText('Upload').closest('tr')!).getByText(/Analysis finding rows:/)).toHaveTextContent('0');
 expect(screen.queryByRole('alert')).not.toBeInTheDocument();expect(screen.getByText(/Zero reported findings does not guarantee security/)).toBeInTheDocument();
});
it('identifies only missing lineages while preserving analyzed findings',()=>{
 render(<PostureEvidence items={[{...item,application_name:'Pump',warning:null},{...item,target_sbom_id:3,application_name:'Pending App',analysis_run_id:null,analysis_finding_rows:null,warning:null}]}/>);
 expect(screen.getByRole('status')).toHaveTextContent('1 without successful analysis evidence');expand();expect(screen.getByText(/Analysis finding rows:/)).toHaveTextContent('81');
});
it('keeps provider coverage warning separate from evidence availability',()=>{
 render(<PostureEvidence items={[{...item,last_known_posture:false,coverage_incomplete:true,warning:'Analysis coverage incomplete: GITHUB unavailable.'}]}/>);
 expect(screen.getByRole('status')).toHaveTextContent('1 with incomplete source coverage');expand();expect(screen.getByText(/Analysis coverage incomplete/)).toBeInTheDocument();
});
it('shows loading without declaring missing evidence',()=>{
 api.mockImplementation(()=>new Promise(()=>{}));notice();expect(screen.getByRole('status',{name:'Loading version evidence'})).toBeInTheDocument();expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it('shows retryable HTTP 500 separately from counts and recovers',async()=>{
 api.mockRejectedValue(Object.assign(new Error('server failed'),{status:500}));notice();
 await screen.findByText(/Version posture request failed.*HTTP 500/,{}, {timeout:4000});expect(screen.queryByText(/Empty counts/)).not.toBeInTheDocument();
 api.mockResolvedValue({items:[{...item,warning:null}]});fireEvent.click(screen.getByRole('button',{name:'Retry version posture'}));await screen.findByRole('button',{name:'Review version evidence'});expand();expect(screen.getByText(/Analysis finding rows:/)).toHaveTextContent('81');expect(screen.queryByText(/HTTP 500/)).not.toBeInTheDocument();
});
it('reports HTTP 403 as permission failure without automatic retry',async()=>{
 api.mockRejectedValue(Object.assign(new Error('forbidden'),{status:403}));notice();await screen.findByText(/permission.*HTTP 403/);expect(api).toHaveBeenCalledTimes(1);expect(screen.queryByText(/Empty counts/)).not.toBeInTheDocument();
});

it('retains labeled cached evidence when refresh fails',async()=>{
 api.mockRejectedValue(Object.assign(new Error('forbidden'),{status:403}));notice({items:[{...item,warning:null}]});
 await screen.findByText(/freshness could not be verified/);expand();expect(screen.getByText(/Analysis finding rows:/)).toHaveTextContent('81');
});

it('mounts no lineage details while collapsed and bounds expanded rows__VEX_UI_001',()=>{
 render(<PostureEvidence items={Array.from({length:1007},(_,i)=>({...item,target_sbom_id:i,application_name:`Application ${i}`}))}/>);
 expect(screen.getByText(/1,007 version lineages/)).toBeInTheDocument();expect(screen.queryByRole('table')).not.toBeInTheDocument();
 expect(screen.queryByText('Application 0')).not.toBeInTheDocument();expand();expect(screen.getAllByRole('row')).toHaveLength(11);
 fireEvent.click(screen.getByRole('button',{name:'Last page'}));expect(screen.getByText('Application 1006')).toBeInTheDocument();expect(screen.getAllByRole('row')).toHaveLength(8);
 fireEvent.change(screen.getByRole('searchbox'),{target:{value:'Application 73'}});expect(screen.getByText('Application 73')).toBeInTheDocument();expect(screen.queryByText('Application 1006')).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Collapse version evidence'}));expect(screen.queryByRole('table')).not.toBeInTheDocument();
});
it('displays completion time separately from finding rows and respects an unavailable effective current version',()=>{
 render(<PostureEvidence items={[{...item,effective_current_sbom:null,analysis_completed_on:'2026-10-22T10:00:00Z'}]}/>);expand();
 expect(screen.getAllByRole('cell')[1]).toHaveTextContent('Unavailable');expect(screen.getByText(/Last successful analysis:/)).not.toHaveTextContent('81');
 expect(screen.getByText(/Last successful analysis:/)).not.toHaveTextContent('Time unavailable');
});
it('labels unknown time and empty search without inventing values',()=>{
 render(<PostureEvidence items={[item]}/>);expand();expect(screen.getByText('Last successful analysis: Time unavailable')).toBeInTheDocument();
 fireEvent.change(screen.getByRole('searchbox'),{target:{value:'absent'}});expect(screen.getByText('No version evidence matches your search.')).toBeInTheDocument();
});
it('shows an empty scope without a disclosure control',()=>{
 render(<PostureEvidence items={[]}/>);expect(screen.getByText('No eligible SBOM versions in this scope.')).toBeInTheDocument();expect(screen.queryByRole('button')).not.toBeInTheDocument();
});
it('does not retain another tenant evidence when the tenant changes__VEX_SEC_002',async()=>{
 api.mockResolvedValueOnce({items:[item]});const view=notice();await screen.findByRole('button',{name:'Review version evidence'});expand();expect(screen.getByText(/Analysis finding rows:/)).toHaveTextContent('81');
 auth.activeTenantId='2';api.mockImplementation(()=>new Promise(()=>{}));view.rerender(<QueryClientProvider client={view.client}><SbomPostureNotice scope={{projectId:null,applicationId:null,sbomId:null}}/></QueryClientProvider>);
 expect(screen.queryByText(/Analysis finding rows:/)).not.toBeInTheDocument();expect(screen.getByRole('status',{name:'Loading version evidence'})).toBeInTheDocument();
});
