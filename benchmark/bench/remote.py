"""Reusable publication and campaign orchestration behind the Fabric tasks."""
from __future__ import annotations
import copy
import math
import re
from pathlib import Path
from .config import Settings, read, ROOT
from .instance import InstanceManager
import alibaba_deployment as cloud
import campaign_execute as execution
import compact_campaign as contract
import deployment_prepare as prep
import remote_native


class Backend:
    def __init__(self, settings, authorization, root, manager_factory=InstanceManager):
        self.settings=settings;self.authorization=authorization;self.root=Path(root)
        self.catalog=read(authorization['catalog']);self.managers={};self.publishers={};self.inventories={}
        self.failed=False;self.manager_factory=manager_factory

    def acquire(self,nodes):
        manager=self.manager_factory(self.settings,nodes);self.managers[nodes]=manager
        try:
            inventory=manager.create()
            self.inventories[nodes]=inventory
            return inventory
        except BaseException:
            self.failed=True;raise

    def publish(self,nodes,protocol):
        key='common' if protocol in ('delugi','raptr') else protocol
        try:
            if (nodes,key) not in self.publishers:
                identity=contract.digest(self.authorization['artifact_bindings'][key])[:24]
                directory=self.managers[nodes].root/'publications'/identity
                directory.mkdir(parents=True,exist_ok=True,mode=0o700)
                publisher=execution.Backend({'catalog':self.authorization['catalog']},directory)
                publisher.inventories[nodes]=self.inventories[nodes]
                self.publishers[nodes,key]=publisher
            return self.publishers[nodes,key].publish(nodes,protocol)
        except BaseException:
            self.failed=True;raise

    def remaining(self,nodes):return self.managers[nodes].remaining()

    def run(self,resolved,output):
        n=resolved['nodes'];p=resolved['protocol'];published=self.publish(n,p)
        mode=self.settings.data['testbeds'][str(n)]['network_mode']
        try:
            if p in ('delugi','raptr'):
                import common_sustained_remote as common
                result=(common.run_delugi(resolved,published,self.catalog['common']['local_verifier'],output,network_mode=mode)
                    if p=='delugi' else common.run_raptr(resolved,published,output,network_mode=mode))
            else:
                values=execution.native_settings(resolved)
                if mode!='controlled':values['network']['mode']=mode
                result=remote_native.execute(remote_native.plan(published,values),output)
            if result.get('status')=='failed':self.failed=True
            return result
        except BaseException:
            self.failed=True;raise

    def release(self,nodes):
        manager=self.managers.get(nodes) or self.manager_factory(self.settings,nodes)
        # An ambiguous prior active trial reaches here without acquire. It must
        # clean the exact previous fleet, never provision a replacement first.
        if nodes in self.managers and self.settings.data['keep_alive'] and not self.failed:
            remaining=manager.remaining()
            finite=math.isfinite(remaining)
            return {'status':'retained','expires_in_s':remaining if finite else None,'provider_auto_release':finite}
        return manager.action('destroy')


class Bench:
    def __init__(self,settings='settings.json',params='parameters.json',*,manager_factory=InstanceManager,backend_factory=Backend):
        self.settings=Settings(settings);self.params=read(params)
        self.plan,self.resolved=self.settings.plan(self.params)
        self.manager_factory=manager_factory;self.backend_factory=backend_factory

    def describe(self):
        return {'plan':self.plan,'resolved':self.resolved,'no_cloud_calls':True,'no_ssh':True}

    def validate(self):
        # Every selected adapter and binary is checked before provisioning.
        catalog=read(self.settings.data['artifacts'])
        selected=({'common'} if set(self.plan['config']['protocols'])&{'delugi','raptr'} else set())|{p for p in self.plan['config']['protocols'] if p in execution.NATIVE}
        if not selected<=set(catalog):raise ValueError('saved artifact catalog lacks selected implementations')
        # Allow a reusable superset catalog while retaining exact selected roles.
        bindings=execution.validate_artifacts(self.plan['config'],{p:catalog[p] for p in selected})
        return bindings

    def lifecycle(self,action):
        self.settings.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        with cloud.lease_lock(self.settings.root/'dispatch'):
            return self._lifecycle(action)

    def _lifecycle(self,action):
        result={}
        for n in self.plan['config']['committees']:
            manager=self.manager_factory(self.settings,n)
            result[str(n)]=manager.create() if action=='create' else manager.action(action)
        return result

    def install(self):
        self.validate()
        self.settings.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        with cloud.lease_lock(self.settings.root/'dispatch'):
            return self._install()

    def _install(self):
        bindings=self.validate()
        authorization={'catalog':self.settings.data['artifacts'],'artifact_bindings':bindings}
        backend=self.backend_factory(self.settings,authorization,self.settings.root/'installation')
        records={}
        try:
            for n in self.plan['config']['committees']:
                backend.acquire(n)
                records[str(n)]={p:backend.publish(n,p) for p in self.plan['config']['protocols']}
        except BaseException:
            backend.failed=True
            for n in backend.managers:backend.release(n)
            raise
        return {'status':'installed','committees':list(records),'reuses_publications':True}

    def remote(self,name=None):
        self.validate()
        self.settings.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        with cloud.lease_lock(self.settings.root/'dispatch'):
            return self._remote(name)

    def _remote(self,name=None):
        if name is not None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',name):
            raise ValueError('run name must be a short filename component')
        bindings=self.validate()
        output=self.settings.root/'runs'/(name or self.plan['plan_sha256'][:24])
        auth={'schema':1,'kind':'delugi-fabric-run-v1','plan_sha256':self.plan['plan_sha256'],
            'catalog':self.settings.data['artifacts'],'artifact_bindings':bindings,
            'settings':copy.deepcopy(self.settings.data),
            'controller_sources':{str(p.relative_to(ROOT)):prep.sha(p) for p in sorted((ROOT/'benchmark').rglob('*.py'))}}
        def validate(plan,authorization):
            if plan!=self.plan or authorization!=auth:raise ValueError('run identity changed')
            if self.validate()!=bindings:raise ValueError('artifact changed after planning')
            return bindings
        def backend(authorization,root):
            return self.backend_factory(self.settings,authorization,root,manager_factory=self.manager_factory)
        state=execution.execute(self.plan,auth,output,validate=validate,backend_factory=backend,
            minimum_remaining_s=self.settings.data['timeouts']['minimum_remaining_s'])
        return {'status':state['status'],'output':str(output),'runs':len(state['rows']),
                'results':str(output/'results.csv'),'error':state.get('error')}

    def logs(self,name=None):
        from .logs import LogParser
        return LogParser(self.run_directory(name)).export()

    def run_directory(self,name=None):
        if name is not None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',name):raise ValueError('invalid run name')
        return self.settings.root/'runs'/(name or self.plan['plan_sha256'][:24])


def manage(settings, action):
    """Cleanup never depends on a valid workload, specification or artifacts."""
    selected=Settings(settings)
    selected.root.mkdir(parents=True,exist_ok=True,mode=0o700)
    with cloud.lease_lock(selected.root/'dispatch'):
        nodes=set(selected.data['testbeds'])
        nodes.update(p.parent.name for p in (selected.root/'testbeds').glob('*/current.json'))
        if not nodes<=set(('4','10','50')):raise ValueError('unexpected saved testbed identity')
        return {n:InstanceManager(selected,int(n)).action(action) for n in sorted(nodes,key=int)}
