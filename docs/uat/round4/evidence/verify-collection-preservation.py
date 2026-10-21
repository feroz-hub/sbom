from pathlib import Path
import json,re
from collections import Counter
D=Path(__file__).resolve().parent
old=json.loads((D.parents[1]/'round3/evidence/backend-execution-inventory.json').read_text())
new=json.loads((D/'acceptance-inventory.json').read_text())
aliases={'tests/test_functional_security_compatibility.py::test_list_error_contract_is_preserved_without_mutations[params2-400]':'tests/test_functional_security_compatibility.py::test_list_error_contract_is_preserved_without_mutations[params2-422]'}
def canonical(s):
 s=aliases.get(s,s); prefix='tests/test_component_advisor_api.py::test_historical_or_invalid_as_of_is_rejected__D11['
 if s.startswith(prefix) and s.endswith(']') and s[len(prefix):-1]!='yesterday':s=prefix+'historical-date]'
 return s
def sanitized(s):
 s=re.sub(r'\[REDACTED_CONNECTION_SHA256_[0-9a-f]+\]', '[REDACTED_CONNECTION]',s)
 return re.sub(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+','[REDACTED_CONNECTION]',canonical(s))
before=Counter(sanitized(x['nodeid']) for x in old);after=Counter(sanitized(x['nodeid']) for x in new)
missing=list((before-after).elements());added=list((after-before).elements())
assert sum(before.values())==4368 and sum(after.values())==4392
assert not missing,missing
assert len(added)==24,added
out={'originalCount':sum(before.values()),'currentCount':sum(after.values()),'missingOriginalNodes':missing,'addedNodes':added,'intentionalSelectorAlias':aliases,'dynamicDateNormalization':'Only D11 nonliteral historical datetime parameter','historicalRedactionQualification':'Three database-safety parameter selectors were already identically redacted in the historical register. Comparison preserves their multiplicity rather than collapsing them into one node. The current unchanged source retains the three distinct rejected synthetic URLs.','result':'PASS'}
(D/'collection-preservation.json').write_text(json.dumps(out,indent=2)+'\n')
print('All 4368 original nodes preserved; 24 new nodes; no missing tests')
