from pathlib import Path
import json,xml.etree.ElementTree as ET
D=Path(__file__).resolve().parent
rows=[]
for p in sorted(D.glob('*.xml')):
 root=ET.parse(p).getroot();cases=list(root.iter('testcase'));fail=sum(x.find('failure') is not None for x in cases);err=sum(x.find('error') is not None for x in cases);skip=sum(x.find('skipped') is not None for x in cases)
 rows.append({'file':p.name,'JUnitTestcasesIncludingSubtests':len(cases),'PASS':len(cases)-fail-err-skip,'FAIL':fail,'ERROR':err,'SKIP':skip,'runtimeSeconds':sum(float(x.get('time',0)) for x in root.findall('testsuite')) if root.tag=='testsuites' else float(root.get('time',0)),'qualification':'Overlapping selections; never add to unique totals. JUnit may include subtests separately.'})
(D/'junit-run-index.json').write_text(json.dumps(rows,indent=2)+'\n')
print('Indexed',len(rows),'preserved JUnit documents')
