from pathlib import Path
from collections import Counter
import json
D=Path(__file__).resolve().parent
r=json.loads((D.parent/'ROUND4_TEST_RESULTS.json').read_text())
groups={
 'SBO-70 VEX serialization, concurrency and authorization':['tests/test_vex_confidence_serialization.py','tests/test_vex_audit_concurrency.py','tests/test_vex_investigations_api.py','tests/test_vex_scoped_authorization.py'],
 'SBO-71 Dashboard UUID hierarchy':['tests/test_dashboard_scope.py'],
 'SBO-76 Advisor policy history':['tests/test_policy_public_identity.py'],
 'SBO-74 KEV permissions':['tests/test_kev_router.py','tests/test_kev_sync_worker.py'],
 'Native IAM and Users & Access':['tests/test_native_iam_foundation.py','tests/test_native_iam_phase2.py','tests/test_native_iam_phase3.py','tests/test_native_iam_phase4.py','tests/test_native_iam_phase5.py','tests/test_native_iam_acceptance.py','tests/test_phase9_role_assignment_api.py'],
 'Repair candidate-byte integrity':['tests/test_repair_candidate_public_boundary.py'],
 'CUSTOM cron and Monthly scheduling':['tests/test_scheduling_service.py','tests/test_schedules_api.py'],
 'Native absolute session expiry':['tests/test_native_session_lifetime.py'],
 'Legacy analysis UUID boundaries':['tests/test_legacy_analysis_public_identity.py'],
 'Round 4 scoped batch and operator fixes':['tests/test_public_identity_batch_serialization.py','tests/test_reconcile_analysis_run_scope.py','tests/test_round4_uuid_regression.py']}
out=[]
for name,files in groups.items():
 nodes=[t for t in r['tests'] if t['nodeid'].split('::')[0] in files]
 assert nodes,name
 out.append({'name':name,'files':files,'counts':dict(Counter(t['outcome'] for t in nodes)),'tests':[{'nodeid':t['nodeid'],'evidenceNode':t['evidenceNode'],'outcome':t['outcome']} for t in nodes]})
(D/'prior-round-protection-register.json').write_text(json.dumps({'qualification':'Actual frozen-run outcomes only. Groups overlap; never sum into unique totals. Frontend popup, wording, Dashboard and HTTP503 use full final Vitest evidence separately.','groups':out},indent=2)+'\n')
print('Protection groups:',len(out))
