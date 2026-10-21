"""Select every original exact node after collection; fail closed on mismatches."""
import json
from pathlib import Path
import pytest

def pytest_collection_modifyitems(config, items):
    wanted = set(json.loads(Path(__file__).with_name('remaining-backend-nodes.json').read_text()))
    selected = [item for item in items if item.nodeid in wanted]
    missing = wanted - {item.nodeid for item in selected}
    if missing:
        raise pytest.UsageError('Unresolved original selectors: ' + repr(sorted(missing)))
    deselected = [item for item in items if item.nodeid not in wanted]
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
