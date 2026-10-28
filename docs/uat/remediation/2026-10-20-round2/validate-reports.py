"""Validate report links and scan evidence for credential-shaped values without printing them."""
from pathlib import Path
import json
import re

out = Path(__file__).resolve().parent
missing = []
for p in [out / name for name in ('RESULTS.md', 'LINEAR_RESULTS.md', 'SBO-73_DECISION_PROPOSAL.md', 'SBO-54_FAILURE_CLASSIFICATION.md')]:
    for ref in re.findall(r'\]\(([^)]+)\)', p.read_text()):
        if not ref.startswith(('https:', 'http:', '#')) and not (p.parent / ref).exists():
            missing.append([p.name, ref])
patterns = [re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), re.compile(r'(?im)^\s*(?:set-cookie|authorization|cookie)\s*:\s*(?!\[REDACTED\])\S+')]
markers = []
classified = []
for p in out.rglob('*'):
    if not p.is_file() or p.suffix == '.png':
        continue
    try:
        s = p.read_text()
    except UnicodeDecodeError:
        continue
    for pattern in patterns:
        for m in pattern.finditer(s):
            value = m.group().split(':', 1)[-1].strip()
            if p.suffix == '.py' and value.startswith(('str', 'Optional', 'Annotated', 'reads', 'decisions')):
                classified.append({'file': str(p.relative_to(out)), 'classification': 'source documentation or Python parameter annotation; reviewed, no credential'})
            else:
                markers.append(str(p.relative_to(out)))
checks = {'reportLinksMissing': missing, 'credentialLikeValueMatches': markers, 'reviewedFalsePositives': classified, 'finalCaseRegister': json.loads((out / 'case-summary.json').read_text())['byExecutionKind'], 'sourceFilesChanged': len(json.loads((out / 'changed-files.json').read_text())), 'result': 'FAIL' if missing or markers else 'PASS'}
(out / 'report-validation.json').write_text(json.dumps(checks, indent=2))
print(json.dumps(checks, indent=2))
assert checks['result'] == 'PASS'
