from pathlib import Path
from collections import Counter
import datetime,hashlib,json,re
D=Path(__file__).resolve().parent
second=(D/'frozen-acceptance-attempt2-manifest.json').exists()
manifest='frozen-acceptance-attempt2-manifest.json' if second else 'frozen-acceptance-manifest.json'
path=D/('acceptance-attempt2-outcomes.jsonl' if second else 'acceptance-outcomes.jsonl')
def display(node):
 return re.sub(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+',lambda m:'[REDACTED_CONNECTION_SHA256_'+hashlib.sha256(m.group().encode()).hexdigest()[:12]+']',node)
rows=[json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []
rows=[r for r in rows if not r.get('isSubtest')]
by_node={}
for r in rows:
 if r['nodeid'] not in by_node or by_node[r['nodeid']]['outcome']!='failed':by_node[r['nodeid']]=r
rows=list(by_node.values())
m=json.loads((D/manifest).read_text());result={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'attempt':2 if second else 1,'status':m['status'],'counts':dict(Counter(r['outcome'] for r in rows)),'lastNode':display(rows[-1]['nodeid']) if rows else None,'failedNodes':[display(r['nodeid']) for r in rows if r['outcome']=='failed']}
if m['status']=='FINISHED':result.update({k:m.get(k) for k in ('exitCode','runtimeSeconds','sourceUnchangedDuringRun','changedSourceFiles')})
if (D/'validation-results.json').exists():
 v=json.loads((D/'validation-results.json').read_text());result['validationStatus']=v['status'];result['checks']=[{k:r.get(k) for k in ('name','outcome','runtimeSeconds')} for r in v['checks']]
(D/'PROGRESS.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
