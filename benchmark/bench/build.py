"""Saved asynchronous common Linux build, reusing the Fabric testbed."""
from pathlib import Path
import subprocess
from .config import Settings, read, ROOT
from .instance import InstanceManager
import alibaba_deployment as cloud
import aliyun_bench
import common_cloud_controller as controller
import deployment_prepare as prep


def execute(settings, action, nodes=4, revision=None):
    selected=Settings(settings);selected.root.mkdir(parents=True,exist_ok=True,mode=0o700)
    pointer=selected.root/'common-build.json'
    with cloud.lease_lock(selected.root/'dispatch'):
        if action=='dispatch':
            revision=revision or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
            controller.worker.revision(revision)
            if subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,text=True).strip():
                raise ValueError('commit and push the build sources before dispatch')
            manager=InstanceManager(selected,int(nodes));inventory=manager.create()
            root=manager.root/'builds'/revision;root.mkdir(parents=True,exist_ok=True,mode=0o700)
            path=root/'plan.json'
            if not path.exists():prep.json_file(path,controller.make_plan(inventory,revision,install_packages=True))
            plan=read(path)
            prep.json_file(pointer,{'plan':str(path),'root':str(root)})
        else:
            saved=read(pointer);path=Path(saved['plan']);root=Path(saved['root']);plan=read(path)
        connection=aliyun_bench.Connection(plan['host'])
        with aliyun_bench.campaign_connections():
            if action=='dispatch':return {'plan':str(path),'launcher':controller.dispatch(plan,connection)}
            state=controller.status(plan,connection)
            if action=='status':return state
            if action!='collect':raise ValueError('unknown build action')
            if state.get('status',{}).get('status') not in ('completed','failed'):
                raise ValueError('build is still running; inspect build-status')
            output=root/'collected'
            if (output/'collection.json').is_file():
                result=read(output/'collection.json')
                result={'status':result['status'],'publication':str(output/'publication.json') if result['status']=='completed' else None,'directory':str(output)}
            else:result=controller.collect(plan,connection,output)
            if result['status']=='completed':
                catalog=read(selected.data['artifacts']);catalog['common']['publication']=result['publication']
                prep.json_file(Path(selected.data['artifacts']),catalog)
            return result
