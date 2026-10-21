"""Read timings on a fixed task-owned test DB; never selects a runtime DB."""
import importlib.util,os,time,json
from pathlib import Path
out=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r3wrapper',out/'run-fix-regressions.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
url=w.url('greenfield_setup','setup-password');os.environ.update(TEST_DATABASE_URL=url,TEST_POSTGRES_DATABASE_URL=url,DATABASE_URL=url,PYTHON_DOTENV_DISABLED='1')
import tests.conftest as c
from sqlalchemy import create_engine,text
engine=create_engine(url,isolation_level='AUTOCOMMIT',hide_parameters=True)
# Existing exact cleanup, including sequence reset.
start=time.perf_counter();c._truncate_postgres_application_tables(url);baseline=time.perf_counter()-start
with engine.connect() as conn:
 names=list(conn.execute(text("SELECT format('%I.%I',schemaname,tablename) FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version' AND tablename NOT IN ('authorization_roles','authorization_permissions','authorization_role_permissions') ORDER BY tablename")).scalars())
 start=time.perf_counter()
 separate=[name for name in names if conn.execute(text(f'SELECT EXISTS (SELECT 1 FROM {name} LIMIT 1)')).scalar()];old=time.perf_counter()-start
 statement=' UNION ALL '.join(f'SELECT :n{i} AS table_name WHERE EXISTS (SELECT 1 FROM {name} LIMIT 1)' for i,name in enumerate(names))
 start=time.perf_counter();batched=list(conn.execute(text(statement),{f'n{i}':name for i,name in enumerate(names)}).scalars());new=time.perf_counter()-start
 result={'testDatabase':w.DB,'tablesInspected':len(names),'existingFullCleanupSeconds':baseline,'separateExactChecksSeconds':old,'batchedExactChecksSeconds':new,'identicalExactTableSet':set(separate)==set(batched),'noApproximateStatistics':True}
(out/'cleanup-measurement.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));assert result['identicalExactTableSet']
import inspect
source=inspect.getsource(c._truncate_postgres_application_tables)
source=source.replace('def _truncate_postgres_application_tables(', 'def transactional_cleanup(').replace('create_engine(database_url, isolation_level="AUTOCOMMIT")','create_engine(database_url)').replace('with engine.connect() as connection:', 'with engine.begin() as connection:')
namespace=dict(c.__dict__);exec(source,namespace)
c._seed_postgres_test_tenant(url)
start=time.perf_counter();namespace['transactional_cleanup'](url);atomic=time.perf_counter()-start
with engine.connect() as conn:
 remaining=list(conn.execute(text(statement),{f'n{i}':name for i,name in enumerate(names)}).scalars())
 result.update(transactionalFullCleanupSeconds=atomic,transactionalCleanupEmpty=not remaining,transactionalCodeChanges='Same exact cleanup and guards; use one committed transaction instead of per-statement autocommit')
(out/'cleanup-measurement-transactional.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));assert not remaining
engine.dispose()
