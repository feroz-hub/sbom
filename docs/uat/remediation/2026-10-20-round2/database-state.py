"""Read-only verification of the exact isolated database target and revision."""
import json,os
from pathlib import Path
from sqlalchemy import create_engine,text
from sqlalchemy.engine import make_url
from scripts.dev import GreenfieldStack
settings = GreenfieldStack.settings
configuration=settings();u=make_url(configuration['DATABASE_URL']);assert (u.host,u.port,u.database)==('127.0.0.1',56044,'sbom_greenfield_uuid')
engine=create_engine(configuration['DATABASE_URL'],hide_parameters=True)
with engine.connect() as c:
 revision=c.execute(text('SELECT version_num FROM alembic_version')).scalar_one()
 database=c.execute(text('SELECT current_database()')).scalar_one()
e={'database':database,'revision':revision,'expectedRevision':'100_greenfield_uuid_final','readOnly':True,'result':'PASS' if database=='sbom_greenfield_uuid' and revision=='100_greenfield_uuid_final' else 'FAIL'}
(Path(__file__).resolve().parent/'database-state.json').write_text(json.dumps(e,indent=2));print(e)
