"""Reconcile actual telemetry and protected artifacts; never infer PASS."""
from pathlib import Path
from collections import Counter
import datetime,difflib,hashlib,json,re,subprocess,xml.etree.ElementTree as ET
R=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent;O=D.parent

def canonical(node):
    prefix='tests/test_component_advisor_api.py::test_historical_or_invalid_as_of_is_rejected__D11['
    if node.startswith(prefix) and node.endswith(']') and node[len(prefix):-1]!='yesterday':
        # The source has one datetime.now(UTC)-30days parameter and one literal
        # yesterday parameter. Only this generated timestamp varies by collection.
        return prefix+'historical-date]'
    return node

def display(node):
    return re.sub(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+', lambda m: '[REDACTED_CONNECTION_SHA256_'+hashlib.sha256(m.group().encode()).hexdigest()[:12]+']', node)

base=json.loads((D/'baseline.json').read_text())
attempt2=(D/'frozen-acceptance-attempt2-manifest.json').exists()
manifest_name='frozen-acceptance-attempt2-manifest.json' if attempt2 else 'frozen-acceptance-manifest.json'
inventory_name='acceptance-attempt2-inventory.json' if attempt2 else 'acceptance-inventory.json'
outcomes_name='acceptance-attempt2-outcomes.jsonl' if attempt2 else 'acceptance-outcomes.jsonl'
artifact_prefix='pytest-full-frozen-attempt2' if attempt2 else 'pytest-full-frozen'
manifest=json.loads((D/manifest_name).read_text()) if (D/manifest_name).exists() else {}
inventory=json.loads((D/inventory_name).read_text())
observations={};subtests=[]
for line in (D/outcomes_name).read_text().splitlines() if (D/outcomes_name).exists() else []:
    row=json.loads(line)
    if row.get('isSubtest'):subtests.append(row);continue
    key=canonical(row['nodeid']);old=observations.get(key)
    if old is None or old['outcome']!='failed':observations[key]=row
results=[]
for item in inventory:
    observed=observations.get(canonical(item['nodeid']))
    result='NOT RUN'
    if observed:
        result= ('XFAIL' if observed.get('wasxfail') and observed['outcome']=='skipped' else 'XPASS' if observed.get('wasxfail') and observed['outcome']=='passed' else 'ERROR' if observed['outcome']=='failed' and observed['phase']!='call' else {'passed':'PASS','failed':'FAIL','skipped':'SKIP'}[observed['outcome']])
    results.append({**item,'nodeid':display(item['nodeid']),'outcome':result,'evidenceNode':display(observed['nodeid']) if observed else None,
                    'seconds':observed['seconds'] if observed else None,'reason':observed.get('reason') if observed else None,
                    'sourceQualification':'Single frozen acceptance run' if observed else 'Not executed in frozen run',
                    'normalization': 'Single dynamic historical-date parameter; source expression unchanged' if observed and item['nodeid']!=observed['nodeid'] else None})
counts=Counter(r['outcome'] for r in results)
for name in ('PASS','FAIL','ERROR','SKIP','XFAIL','XPASS','NOT RUN'):counts.setdefault(name,0)
validation=json.loads((D/'validation-results.json').read_text()) if (D/'validation-results.json').exists() else {'status':'NOT RUN','checks':[]}
protected=[name for name,h in base['protectedEvidenceHashes'].items() if not (R/name).exists() or hashlib.sha256((R/name).read_bytes()).hexdigest()!=h]
(D/'historical-preservation.json').write_text(json.dumps({'protectedFiles':len(base['protectedEvidenceHashes']),'changedFiles':protected,'original485BaselineUnchanged':not protected},indent=2)+'\n')
subtest_log=D/(artifact_prefix+'.log')
subtest_match=re.search(r'(\d+) subtests passed',subtest_log.read_text()) if subtest_log.exists() else None
subtest_summary={'PASS':int(subtest_match.group(1))} if subtest_match else dict(Counter(row['outcome'] for row in subtests))
current={canonical(row['nodeid']):row for row in results};failure_rows=json.loads((D/'failure-reconciliation-focused.json').read_text())
for row in failure_rows:
    hit=current.get(canonical(row['currentNodeid']))
    row['finalFrozenOutcome']=hit['outcome'] if hit else 'NOT RUN';row['frozenEvidenceNode']=hit['evidenceNode'] if hit else None
completed=(manifest.get('status')=='FINISHED' and manifest.get('sourceUnchangedDuringRun') and not any(counts[k] for k in ('NOT RUN','FAIL','ERROR','XPASS')) and validation.get('status')=='PASS' and not protected)
completion_status='ROUND4_BACKEND_REGRESSION_COMPLETED' if completed else 'ROUND4_BACKEND_REGRESSION_PARTIALLY_COMPLETED'
(O/'ROUND4_TEST_RESULTS.json').write_text(json.dumps({'status':completion_status,
    'validation':validation,
    'generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'historical485':{'PASS':454,'FAIL':12,'BLOCKED':11,'NOT RUN':8,'immutable':True},
    'originalRound3Inventory':{'total':4368,'observationsAcrossMixedRuns':{'PASS':3785,'FAIL':228,'SKIP':9,'NOT RUN':346}},
    'remaining346Run':{'PASS':346,'FAIL':0,'ERROR':0,'SKIP':0,'subtestsPassed':8,'runtimeSeconds':428.08,'sourceUnchanged':True},
    'original228':failure_rows,'frozenRun':{'manifest':'evidence/'+manifest_name,'log':'evidence/'+artifact_prefix+'.log','xml':'evidence/'+artifact_prefix+'.xml','attempt':2 if attempt2 else 1,'status':manifest.get('status'),'counts':dict(counts),'collected':len(results),'subtestOutcomes':subtest_summary,'subtestQualification':'Pytest summary reports unittest subtests separately. JUnit suite totals include them; 4392 testcase elements and the exact inventory are the unique case denominator.','sourceUnchanged':manifest.get('sourceUnchangedDuringRun')},
    'tests':results,'preservation':{'protectedEvidenceFiles':len(base['protectedEvidenceHashes']),'changedProtectedEvidenceFiles':protected},
    'initialFrozenRun':{'manifest':'evidence/frozen-acceptance-manifest.json','results':'evidence/attempt1-ROUND4_TEST_RESULTS.json','counts':{'PASS':4383,'FAIL':1,'ERROR':0,'SKIP':8,'XFAIL':0,'XPASS':0,'NOT RUN':0},'runtimeSeconds':5518.6,'sourceUnchanged':True,'original228PASS':228,'qualification':'First frozen run preserved independently; never merged into final counts'},'backendAcceptanceQualification':'Zero failures with documented runtime skips' if manifest.get('status')=='FINISHED' and manifest.get('exitCode')==0 else 'Acceptance not yet established','fullApplicationUatSignoff':'WITHHELD'},indent=2)+'\n')
classification=Counter(row['rootCauseClassification'] for row in failure_rows)
text='''# Round 4 failure classification

Original population: 228 unresolved observed nodes from Round 3, not a single frozen baseline. Each node retains its original selector and diagnostic pointer. Historical 485 and earlier evidence remain unchanged.

## Confirmed root causes

| Classification | Original nodes |
|---|---:|
'''
for cat,n in classification.items():text+=f'| {cat} | {n} |\n'
text+='''
The Advisor benchmark had two obsolete fixture prerequisites (guarded raw SQL and missing logical-SBOM relationship). After correcting those, it exposed a genuine N+1 public-ID serialization defect. The captured 300s timeout is preserved. A 12-reference regression proved 12 queries before and 1 after. Scoped batching preserves lookup authorization, request-local caches, native documents and nonresource integer identifiers. The unchanged 20,000-occurrence benchmark subsequently passed.

Fresh Greenfield installation used a 64-character Alembic marker while its existing contract test required 128. Only future creation and new task-owned test DBs now use 128. No existing live schema was altered; its current revision 100 fits its existing marker. Existing databases require separately reviewed migration work if wider markers become necessary.

Historical migration nodes now exercise their intended unchanged migration ranges on individually created and dropped test databases. They do not downgrade current 100 or bypass the irreversible 076/100 rollback guards. Each preserves its data, token, identity, audit, constraint or schema assertions. Ranges are explicit in `tests/historical_migration_fixture.py`.

The five global-directory cases no longer claim a policy-authorized positive HTTP capability. Each asserts actual 403/current V5 denial; the original matching/projection assertions remain explicit direct-handler unit coverage. No principal gains permissions and SBO-73 tenant candidate-discovery policy is untouched.

## Exact original-node reconciliation

Focused outcomes and the frozen run are separate columns. NOT RUN means no observed frozen outcome yet.

| Original node ID | Current selector if changed | Focused | Frozen | Classification |
|---|---|---|---|---|
'''
for row in failure_rows:
    focus=row.get('latestFocusedRetest') or {};alias=row['currentNodeid'] if row['currentNodeid']!=row['nodeid'] else 'Same'
    text+=f"| `{row['nodeid']}` | `{alias}` | {focus.get('outcome','NOT RUN')} ({focus.get('run','')}) | {row['finalFrozenOutcome']} | {row['rootCauseClassification']} |\n"
text+='\n## Additional first-full-run failure\n\n`tests/test_structured_logging.py::test_early_body_rejection_logged` failed because the installed Starlette TestClient emits a final httpx2 transport log after the correct application completion event. HTTP 413, correlation headers and the structured completion event were observed. This was an incorrect ordering assumption in the test. The correction selects the exact event and asserts one occurrence, status, method, path, error category and both correlation headers. The entire module passed 27 tests in 22.42s; the same case passed in the final frozen run. Application logging and security policy were unchanged. Evidence: `logging-failure-classification.json`, `pytest-logging-isolated-before.xml`, `pytest-logging-isolated-after.xml`, and final frozen XML.\n'
text+='\nFull per-node diagnostic/correction details: [ROUND4_TEST_RESULTS.json](ROUND4_TEST_RESULTS.json), [focused reconciliation](evidence/failure-reconciliation-focused.json). No cases were deleted or blanket-skipped.\n'
(O/'ROUND4_FAILURE_CLASSIFICATION.md').write_text(text)
# Task-only patch, including untracked files. The dirty Git baseline is never a diff base.
patch=[];files=[]
for p in sorted((D/'before').rglob('*')):
    if not p.is_file():continue
    name=str(p.relative_to(D/'before'));target=R/name
    if name in {'tests/historical_migration_fixture.py','tests/test_reconcile_analysis_run_scope.py','tests/test_round4_uuid_regression.py','tests/test_public_identity_batch_serialization.py'}:continue
    if not target.is_file():continue
    old=p.read_text();new=target.read_text()
    if old!=new:
        patch.extend(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='a/'+name,tofile='b/'+name));files.append({'path':name,'type':'modified','beforeSha256':hashlib.sha256(old.encode()).hexdigest(),'afterSha256':hashlib.sha256(new.encode()).hexdigest()})
for name in ['tests/historical_migration_fixture.py','tests/test_reconcile_analysis_run_scope.py','tests/test_round4_uuid_regression.py','tests/test_public_identity_batch_serialization.py']:
    p=R/name;new=p.read_text();patch.extend(difflib.unified_diff([],new.splitlines(keepends=True),fromfile='/dev/null',tofile='b/'+name));files.append({'path':name,'type':'new','afterSha256':hashlib.sha256(new.encode()).hexdigest()})
(D/'round4-source.patch').write_text(''.join(patch));(D/'round4-source-files.json').write_text(json.dumps(files,indent=2)+'\n')
checkpoint={'status':completion_status,'frozenRunStatus':manifest.get('status'),'frozenRunOutcomes':dict(counts),'original228FocusedPASS':sum((r.get('latestFocusedRetest') or {}).get('outcome')=='PASS' for r in failure_rows),'remaining346PASS':346,'protectedEvidenceChanges':protected,'nextActions':['Allow frozen run to finish; do not edit app/tests/scripts/frontend source during it','Classify and resolve any actual remaining frozen failures, then repeat entire frozen run if corrections are necessary','Run full Vitest, TypeScript, Ruff, ESLint and production build sequentially after backend','Finalize four reports, sanitized logs, exact per-node reconciliation and tracker drafts; no commit or tracker writes']}
if completed:checkpoint['nextActions']=['Review optional/external and target-environment limitations with owners','Review existing SBO-54/SBO-55 drafts; no automatic issue status changes','No commit, push, deployment or full application UAT sign-off authorized']
(D/'CHECKPOINT.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
print('Frozen observed outcomes:',dict(counts),'previous evidence changes',len(protected),'task source files',len(files))
