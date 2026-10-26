"""Controller-side asynchronous Linux build lifecycle. Uses pinned SSH hosts."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import uuid

import common_cloud_build as worker
import deployment_prepare as placement

ROOT = Path(__file__).resolve().parents[1]


def make_plan(inventory, commit, replica=0, install_packages=False):
    placement.validate_hosts(inventory)
    worker.revision(commit)
    host = next(h for h in inventory['hosts'] if h['replica'] == replica)
    nonce = uuid.uuid4().hex
    result = {'schema': 1, 'kind': 'common-linux-build-plan-v1', 'nonce': nonce,
            'host': copy.deepcopy(host), 'revision': commit, 'repository': worker.REPOSITORY,
            'worker_sha256': placement.sha(ROOT/'scripts/common_cloud_build.py'),
            'runtime_sha256': placement.sha(ROOT/'scripts/remote_worker.py'),
            'install_packages': install_packages,
            'ssh_inputs': {name: placement.sha(Path(host[name]).expanduser()) for name in ('identity_file','known_hosts_file')},
            'scope': 'one Linux common release build and tests; no validators or paid instances created',
            'compiler': '1.78.0', 'build_jobs': 1, 'per_cargo_deadline_seconds': 1800,
            'cargo_target_bytes': 20*1024**3, 'cargo_rss_bytes': 8*1024**3, 'comparison_eligible': False}
    result['plan_sha256'] = hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result


def validate(plan, *, dispatch=False):
    if plan.get('kind') != 'common-linux-build-plan-v1' or plan.get('repository') != worker.REPOSITORY:
        raise ValueError('unsupported Linux build plan')
    inputs = {k:v for k,v in plan.items() if k!='plan_sha256'}
    if hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=plan.get('plan_sha256'):
        raise ValueError('build plan changed after planning')
    worker.root_for(plan['nonce']); worker.revision(plan['revision'])
    if type(plan['install_packages']) is not bool: raise ValueError('explicit package installation boolean required')
    host = plan['host']
    for name, expected in plan['ssh_inputs'].items():
        if name not in ('identity_file','known_hosts_file') or placement.sha(Path(host[name]).expanduser()) != expected:
            raise ValueError('build SSH input changed')
    if set(plan['ssh_inputs']) != {'identity_file','known_hosts_file'}:
        raise ValueError('build SSH identity and known-host bindings required')
    if dispatch:
        for name, field in [('common_cloud_build.py','worker_sha256'),('remote_worker.py','runtime_sha256')]:
            if placement.sha(ROOT/'scripts'/name) != plan[field]: raise ValueError('build helper changed after planning')
    return plan


def dispatch(plan, connection):
    validate(plan, dispatch=True)
    root = str(worker.root_for(plan['nonce']))
    owner = {k:plan[k] for k in ('nonce','revision','worker_sha256','runtime_sha256','install_packages')}
    prepare = '''import json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);owner=json.loads(sys.argv[2])
if root.exists():
 if root.is_symlink() or json.loads((root/'owner.json').read_text())!=owner: raise ValueError('unowned build directory')
else:
 root.mkdir(mode=0o700)
 (root/'owner.json').write_text(json.dumps(owner))
 (root/'workers').mkdir(mode=0o700)
'''
    connection.command([connection.python(),'-c',prepare,root,json.dumps(owner)],capture_output=True)
    for name in ('common_cloud_build.py','remote_worker.py'):
        connection.upload(ROOT/'scripts'/name,root+'/workers/'+name)
    start = '''import fcntl,hashlib,json,os,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]);owner=json.loads((root/'owner.json').read_text())
with (root/'launch.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 if (root/'launcher.json').exists():
  print((root/'launcher.json').read_text());sys.exit(0)
 for name,key in [('common_cloud_build.py','worker_sha256'),('remote_worker.py','runtime_sha256')]:
  with (root/'workers'/name).open('rb') as f:
   if hashlib.file_digest(f,'sha256').hexdigest()!=owner[key]: raise ValueError('builder upload differs')
 argv=[sys.executable,str(root/'workers/common_cloud_build.py'),'--nonce',owner['nonce'],'--revision',owner['revision']]
 if owner['install_packages']: argv+=['--install-system-packages']
 with (root/'build.stdout').open('xb') as out,(root/'build.stderr').open('xb') as err:
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
 record={'pid':p.pid,'pid_start':Path(f'/proc/{p.pid}/stat').read_text().rsplit(') ',1)[1].split()[19],'nonce':owner['nonce']}
 (root/'launcher.json').write_text(json.dumps(record));print(json.dumps(record))
'''
    return json.loads(connection.command([connection.python(),'-c',start,root],text=True,capture_output=True).stdout)


def status(plan, connection):
    validate(plan)
    code = '''import json,sys
from pathlib import Path
root=Path(sys.argv[1]);result={}
for name in ('owner','launcher','status'):
 p=root/(name+'.json')
 if p.is_file(): result[name]=json.loads(p.read_text())
if 'launcher' in result:
 p=result['launcher'];proc=Path(f'/proc/{p["pid"]}/stat')
 try: result['worker_alive']=proc.read_text().rsplit(') ',1)[1].split()[19]==p['pid_start']
 except FileNotFoundError: result['worker_alive']=False
print(json.dumps(result))
'''
    return json.loads(connection.command([connection.python(),'-c',code,str(worker.root_for(plan['nonce']))],text=True,capture_output=True).stdout)


def collect(plan, connection, output):
    validate(plan)
    root = str(worker.root_for(plan['nonce']))
    output = Path(output).resolve(); output.mkdir(parents=True, mode=0o700, exist_ok=False)
    archive = output/'build-evidence.tar'
    with archive.open('xb') as out:
        connection.command([connection.python(),root+'/workers/common_cloud_build.py','--nonce',plan['nonce'],'--export'],
                           stdout=out,stderr=subprocess.PIPE,timeout=1800)
    if archive.stat().st_size > worker.MAX_EXPORT+1024**2: raise ValueError('build collection exceeded bound')
    total = 0; seen = set(); files = output/'files'; files.mkdir(mode=0o700)
    with tarfile.open(archive) as incoming:
        for member in incoming:
            name = member.name; placement.relative(name)
            if not member.isfile() or name in seen: raise ValueError('unsafe build evidence member')
            seen.add(name); total += member.size
            if total > worker.MAX_EXPORT or len(seen)>2048: raise ValueError('build evidence exceeds envelope')
            path = files/name; path.parent.mkdir(parents=True, exist_ok=True)
            with incoming.extractfile(member) as src, path.open('xb') as out: shutil.copyfileobj(src,out,1024**2)
    state = json.loads((files/'status.json').read_text())
    if any(state.get(k)!=plan[k] for k in ('nonce','revision','worker_sha256','runtime_sha256')):
        raise ValueError('collected build belongs to another plan')
    if state.get('status') == 'completed':
        remote = json.loads((files/'publication/publication.json').read_text())
        binary_archive = files/'publication/common-node.tar.gz'
        if placement.sha(binary_archive)!=remote['sha256']: raise ValueError('collected publication changed')
        local = dict(remote, archive=str(binary_archive))
        placement.json_file(output/'publication.json',local)
    placement.json_file(output/'collection.json',{'sha256':placement.sha(archive),'files':sorted(seen),'status':state['status']})
    return {'status':state['status'],'directory':str(output),'publication':str(output/'publication.json') if state['status']=='completed' else None}
