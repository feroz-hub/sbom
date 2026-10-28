"""Index saved observations without converting diagnostic failures into acceptance."""
import json,re
from pathlib import Path
from collections import Counter
out=Path(__file__).resolve().parent
logs=[]
for p in sorted(out.glob('*.log')):
 text=p.read_text(errors='replace');summaries=re.findall(r'(?m)^.*\b\d+ (?:passed|failed|skipped).*$',text)
 terminal=[s.strip() for s in summaries if not s.startswith(('FAILED','E ')) and (' in ' in s or s.strip().startswith('Tests '))]
 if not terminal:continue
 summary=terminal[-1];counts={k:sum(int(x) for x in re.findall(r'(\d+) '+k+r'\b',summary)) for k in ['passed','failed','skipped']}
 logs.append({'log':p.name,'summary':summary,'counts':counts,'acceptance':p.name in {'pytest-vex-final.log','pytest-native-final.log','vitest-all-final.log'}})
(out/'execution-index.json').write_text(json.dumps(logs,indent=2))
accepted=[('api-policy.json','Advisor policy history','live-policy.py'),('browser-policy.json','Advisor policy history','live-policy-browser.py'),('api-kev.json','KEV authorization','live-kev.py'),('browser-kev.json','KEV role presentation','browser-round2.cjs kev'),('browser-kev-scope.json','KEV browser global action','browser-kev-scope.cjs'),('browser-after.json','Member candidate popup','browser-round2.cjs after'),('browser-membership.json','Membership confirmation/lifecycle','browser-membership.cjs membership'),('browser-candidate-visual.json','Candidate popup geometry','browser-candidate-visual.cjs candidate-visual'),('api-vex-source-document-after.json','VEX native source document','live-vex-document-after.py'),('api-round1-final.json','Round 1 VEX protection','api-final-protection.py'),('api-dashboard.json','Round 1 dashboard protection','dashboard-api.py'),('browser-dashboard-accepted.json','Round 1 dashboard browser','browser-dashboard.cjs'),('browser-protection-vex.json','Round 1 VEX browser','browser-protection.cjs vex'),('browser-protection-vex-readback.json','Round 1 VEX browser','browser-protection.cjs vex-readback'),('final-guards.json','Identity/environment safeguards','final-guards.py')]
rows=[]
for filename,module,script in accepted:
 p=out/filename
 if not p.exists():continue
 data=json.loads(p.read_text());items=data if isinstance(data,list) else data.get('checks',[])
 for i,item in enumerate(items):
  ident=item.get('id',module+'-'+str(i+1));before=ident.startswith('R2-POLICY-BEFORE-')
  actual=item.get('actual',item);status=actual.get('status') if isinstance(actual,dict) else None
  role=item.get('role','as recorded in script')
  if filename=='api-policy.json':
   if '-ROLE-' in ident or '-WRITE-DENY-' in ident:role=ident.rsplit('-',1)[-1]
   elif '-ISOLATION-' in ident:role='foreign tenant administrator in own tenant'
   elif '-PLATFORM-' in ident or ident=='R2-POLICY-CLEANUP':role='platform administrator'
   else:role='disposable tenant administrator'
  rows.append({'testCaseId':ident,'module':module,'role':role,'preconditions':item.get('preconditions','Isolated live Greenfield UUID environment; authorized disposable fixtures; private Native credentials retained in process memory'),'stepsExecuted':item.get('steps','Execute '+script+'; '+ident),'expectedResult':item.get('expected',str(item.get('expectedStatus','See contract assertion in '+script))),'actualResult':actual,'apiStatus':status,'result':item.get('result','NOT RUN'),'executionKind':'baseline-defect-reproduction' if before else 'acceptance','sanitizedEvidence':filename,'defectReference':{'Advisor policy history':'SBO-76 / UAT-DEF-007','KEV authorization':'SBO-74 / UAT-DEF-005','KEV role presentation':'SBO-74 / UAT-DEF-005','KEV browser global action':'SBO-74 / UAT-DEF-005','Member candidate popup':'SBO-72 / UAT-DEF-001','Membership confirmation/lifecycle':'SBO-75 / UAT-DEF-004','VEX native source document':'SBO-54','Round 1 VEX protection':'SBO-70','Round 1 dashboard protection':'SBO-71','Round 1 dashboard browser':'SBO-71','Round 1 VEX browser':'SBO-70','Candidate popup geometry':'SBO-72 / UAT-DEF-001'}.get(module)})
(out/'TEST_CASES.json').write_text(json.dumps(rows,indent=2))
summary={}
for row in rows:
 key=row['module'];summary.setdefault(key,Counter())[row['result']]+=1
summary={k:dict(v) for k,v in summary.items()}
kinds={}
for row in rows:
 key=row['executionKind'];kinds.setdefault(key,Counter())[row['result']]+=1
summary={'byModule':summary,'byExecutionKind':{k:dict(v) for k,v in kinds.items()},'totalRecords':len(rows)}
(out/'case-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
