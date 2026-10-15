"""Generate the current route report without lifespan execution or DB connections."""
import csv
import inspect
import os
from pathlib import Path

# Inventory must never connect to the configured deployment database.
os.environ['DATABASE_URL'] = 'sqlite://'
from app.core.route_policies import ROUTE_POLICIES
from app.core.route_policy import iter_api_routes, iter_registered_routes, validate_route_policies
from app.main import app

out = Path(__file__).resolve().parent
validate_route_policies(app)
rows = []
api = {id(route): (dependant, inspect.getsource(route.endpoint)) for path, route, dependant in iter_api_routes(app)}

def walk(dependant):
    yield dependant.call
    for child in dependant.dependencies:
        yield from walk(child)

for path, route, _effective in iter_registered_routes(app):
    source = api.get(id(route), (None, ''))[1]
    declared = []
    if id(route) in api:
        for call in walk(api[id(route)][0]):
            try:
                closure = inspect.getclosurevars(call).nonlocals
                if 'permission' in closure:
                    declared.append(str(closure['permission']))
                if 'family' in closure and 'action' in closure:
                    declared.append(f"configuration:{closure['family']}:{closure['action']}")
            except (TypeError, ValueError):
                pass
    for method in sorted(getattr(route, 'methods', ()) or ()):
        policy = ROUTE_POLICIES[f'{method} {path}']
        scope = 'Global/platform' if policy.startswith('platform:') else 'Resolved tenant; explicit/ORM/service checks require individual review'
        if policy == 'public':
            scope = 'Public data or proof-token identity'
        if policy == 'account':
            scope = 'Authenticated account self-service'
        operations = [word for word in ('select','execute','add','delete','commit','flush','refresh') if word+'(' in source]
        rows.append([method,path,getattr(getattr(route,'endpoint',None),'__module__','framework'),
                     'Public/proof-token' if policy=='public' else 'Authenticated account' if policy=='account' else 'Authenticated database-authorized context',
                     policy + ('; additional dependencies: ' + ', '.join(declared) if declared else ''),scope,
                     'Explicit tenant filter/helper observed' if 'tenant_id' in source or '_for_tenant' in source else 'Service/ORM/ownership review required',
                     ', '.join(operations) or 'Service delegation / none',
                     'EXPLICIT PUBLIC' if policy=='public' else 'EXPLICIT ACCOUNT POLICY' if policy=='account' else 'EXPLICIT PERMISSION POLICY AND GUARD'])
with (out/'route-inventory-current.csv').open('w') as f:
    writer=csv.writer(f)
    writer.writerow(['HTTP Method','Endpoint Path','Router','Authentication Requirement','Permission Requirement','Tenant Scope','Resource Ownership Requirement','Database Operation','Security Status'])
    writer.writerows(rows)
print(f'Current inventory: {len(rows)} operations; startup policy validation passed')
