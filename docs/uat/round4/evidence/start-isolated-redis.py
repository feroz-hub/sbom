"""Start only a task-owned ephemeral Redis for the fixed progress-test key."""
from pathlib import Path
import json,socket,subprocess,time
from scripts.greenfield_uuid import STATE
D=Path(__file__).resolve().parent
with socket.socket() as s:
    s.bind(('127.0.0.1',0));port=s.getsockname()[1]
directory=STATE/'round4-redis';directory.mkdir(mode=0o700,exist_ok=True)
log=(directory/'server.log').open('a')
pidfile=directory/'server.pid'
subprocess.run(['/opt/homebrew/bin/redis-server','--bind','127.0.0.1','--port',str(port),'--save','','--appendonly','no','--dir',str(directory),'--daemonize','yes','--pidfile',str(pidfile)],stdout=log,stderr=subprocess.STDOUT,check=True)
import redis
client=redis.Redis(host='127.0.0.1',port=port)
for _ in range(30):
    try:
        if client.ping():break
    except redis.ConnectionError:time.sleep(.1)
else:raise RuntimeError('Owned Redis failed to start')
assert client.dbsize()==0
pid=int(pidfile.read_text().strip())
private=directory/'connection.json';private.write_text(json.dumps({'pid':pid,'port':port}));private.chmod(0o600)
(D/'isolated-redis.json').write_text(json.dumps({'pid':pid,'loopbackPort':port,'persistence':False,'databaseInitiallyEmpty':True,'ownership':'Round4 subprocess only','purpose':'AI_TEST_REDIS_URL fixed key1234; no shared Redis use'},indent=2)+'\n')
print('Task-owned ephemeral Redis ready; connection remains private')
