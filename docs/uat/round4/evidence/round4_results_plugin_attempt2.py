"""Local exact collection/outcome telemetry; never changes test selection."""
import json,time
from pathlib import Path

D=Path(__file__).resolve().parent


def pytest_collection_finish(session):
    if not session.config.option.collectonly:
        return
    rows=[]
    for item in session.items:
        rows.append({'nodeid':item.nodeid,'markers':sorted({m.name for m in item.iter_markers()}),
                     'fixtures':list(getattr(item,'fixturenames',[]))})
    (D/'acceptance-attempt2-inventory.json').write_text(json.dumps(rows,indent=2)+'\n')


def pytest_runtest_logreport(report):
    if report.when=='call' or report.outcome in ('failed','skipped'):
        data={'nodeid':report.nodeid,'phase':report.when,'outcome':report.outcome,'seconds':report.duration,
              'isSubtest':report.__class__.__name__=='SubTestReport','epoch':time.time(),'wasxfail':getattr(report,'wasxfail',None)}
        if report.outcome=='skipped':
            data['reason']=str(report.longrepr)
        with (D/'acceptance-attempt2-outcomes.jsonl').open('a') as stream:
            stream.write(json.dumps(data)+'\n')
