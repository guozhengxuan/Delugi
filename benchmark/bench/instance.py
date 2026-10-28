"""Persistent exact-ID testbeds. Loom supplies saved credentials/placement.

Lease templates are configured once. A new parameter file reuses the live fleet,
its authenticated host keys, and its publications until explicit destruction or
its provider-enforced expiry. This module never deletes a shared VPC or keypair.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import uuid
from .config import read, ROOT
import alibaba_deployment as cloud
import deployment_prepare as prep
import compact_campaign as contract
import wan_overlay


class InstanceManager:
    def __init__(self, settings, nodes):
        self.settings=settings;self.nodes=nodes
        self.selected=settings.data['testbeds'].get(str(nodes))
        self.base=settings.root/'testbeds'/str(nodes)
        self.pointer=self.base/'current.json'
        self.root=None;self.record=None

    def identity(self):
        return contract.digest({'testbed':self.selected,
            'deployment':{k:v for k,v in self.settings.data.items() if k not in ('testbeds','artifacts','keep_alive')},
            'leases':[read(p) for p in self.selected['lease_plans']]})

    def load(self):
        if not self.pointer.exists():return None
        self.root=Path(read(self.pointer)['directory'])
        self.record=read(self.root/'testbed.json')
        return self.record

    def save(self):
        cloud.save(self.root/'testbed.json',self.record)

    def create(self):
        if self.selected is None:raise ValueError('no configuration for this committee')
        self.base.mkdir(parents=True,exist_ok=True,mode=0o700)
        with cloud.lease_lock(self.base/'lifecycle'):
            previous=self.load()
            if previous and not previous.get('closed'):
                if previous['identity']!=self.identity():
                    raise ValueError('live deployment settings changed; destroy the saved testbed before reconfiguring it')
            else:
                self.root=self.base/uuid.uuid4().hex;self.root.mkdir(mode=0o700)
                self.record={'schema':1,'identity':self.identity(),'leases':[], 'closed':False,'status':'preparing','overlay_nonce':uuid.uuid4().hex}
                # Save every ownership record before the first provider mutation.
                for i,path in enumerate(self.selected['lease_plans']):
                    p=dict(cloud.validate_plan(read(path)))
                    ports=self.settings.data['ports']
                    p['peer_port_ranges']=sorted(set(p.get('peer_port_ranges',['1500/1599','8000/8099','9000/9299']))|{str(v)+'/'+str(v) for v in ports.values()})
                    cloud.validate_plan(p);dest=self.root/f'lease-{i}.json'
                    cloud.save(dest,{'run_id':uuid.uuid4().hex[:16],'plan':p})
                    self.record['leases'].append(str(dest))
                self.save();cloud.save(self.pointer,{'directory':str(self.root)})
            if previous and previous.get('status')=='ready' and self.record['leases']:
                if self.remaining()<self.settings.data['timeouts']['minimum_remaining_s']:
                    raise ValueError('saved fleet is near expiry; destroy it before creating a new lease')
                inventory=read(self.root/'inventory.json')
                expected={h['instance_id']:h['ssh'].split('@')[1] for h in inventory['hosts']}
                live=[x for p in self.record['leases'] for x in cloud.Lease(p).refresh()]
                actual={x['InstanceId']:x.get('PublicIpAddress',{}).get('IpAddress',[None])[0] for x in live}
                if actual!=expected or any(x['Status']!='Running' for x in live):
                    raise ValueError('saved fleet changed or stopped; inspect it before reuse')
                return inventory
            if self.selected['inventory']:
                inventory=read(self.selected['inventory']);prep.validate_hosts(inventory)
                if len(inventory['hosts'])!=self.nodes:raise ValueError('inventory committee mismatch')
                old=self.record.get('inventory_sha256');current=contract.digest(inventory)
                if old and old!=current:raise ValueError('saved external inventory changed')
                self.record['inventory_sha256']=current
                cloud.save(self.root/'inventory.json',inventory)
                self.record['status']='ready';self.save();return inventory
            try:
                return self._acquire()
            except BaseException:
                # Keep exact lease identities even if creation had an unknown
                # outcome. destroy() recovers them through the original tokens.
                self.record['status']='setup_failed';self.save()
                raise

    def _acquire(self):
        from alibaba_host_keys import inspect_keys
        timeout=self.settings.data['timeouts'];ssh=self.settings.data['ssh']
        leases=[cloud.Lease(p) for p in self.record['leases']]
        all_instances=[];known_parts=[]
        for i,lease in enumerate(leases):
            if not lease.state.get('batches') or any('ids' not in b for b in lease.state['batches']):
                lease.launch(lease.plan['maximum_instances'])
            deadline=time.monotonic()+timeout['provision_s']
            while time.monotonic()<deadline:
                live=lease.refresh()
                if len(live)==lease.plan['maximum_instances'] and all(x['Status']=='Running' for x in live):break
                time.sleep(timeout['poll_s'])
            else:raise TimeoutError('saved fleet did not become Running')
            auth=self.root/f'host-auth-{i}'
            while time.monotonic()<deadline:
                if inspect_keys(lease.path,auth)['status']=='verified':break
                time.sleep(timeout['poll_s'])
            else:raise TimeoutError('provider-authenticated host keys not ready')
            known_parts.append((auth/'known_hosts').read_text())
            all_instances.extend((lease,x) for x in sorted(live,key=lambda x:x['InstanceId']))
        known=self.root/'known_hosts';known.write_text(''.join(known_parts));known.chmod(0o600)
        hosts=[];overlay=self.selected['overlay'];ports=self.settings.data['ports'];resources=self.settings.data['resources']
        for replica,(lease,item) in enumerate(all_instances):
            inv=prep.hosts_from_loom(self.settings.data['loom_settings'],lease.path,[item['InstanceId']],known,
                user=ssh['user'],cpus=resources['cpus'],memory_bytes=resources['memory_bytes'],
                network_interface=ssh['interface'],python_executable=ssh['python'])
            h=inv['hosts'][0];ip=h['advertised'].split(':')[0]
            if overlay:ip=wan_overlay.address(replica,overlay)
            h.update(replica=replica,advertised=f'{ip}:{ports["consensus"]}',control_port=ports['control'],
                ssh_connect_timeout_s=ssh['connect_timeout_s'],ssh_keepalive_s=ssh['keepalive_s'],ssh_keepalive_count=ssh['keepalive_count'])
            hosts.append(h)
        if overlay:self._overlay(hosts,leases)
        else:
            for lease in leases:lease.peers()
        inventory={'schema':1,'hosts':hosts}
        prep.validate_hosts(inventory);cloud.save(self.root/'inventory.json',inventory)
        self.record.update(status='ready',expires_at=min(l.state['expires_at'] for l in leases));self.save()
        return inventory

    def _overlay(self, hosts, leases):
        from common_sustained_remote import all_ok
        overlay=self.selected['overlay'];nonce=self.record['overlay_nonce'];iface=wan_overlay.identity(nonce)[0]
        helper='/tmp/delugi-wan-helper-'+prep.sha(ROOT/'scripts/wan_overlay.py')+'.py'
        def rpc(h,action,**extra):
            request={'action':action,'nonce':nonce,'replica':h['replica'],'settings':overlay,**extra}
            return json.loads(prep.Connection(h).command([h['python_executable'],helper],
                input=json.dumps(request),text=True,capture_output=True,timeout=self.settings.data['timeouts']['install_s']).stdout)
        def install(h):
            c=prep.Connection(h)
            code="import os,subprocess;env=dict(os.environ,DEBIAN_FRONTEND='noninteractive');subprocess.run(['apt-get','update'],env=env,check=True,stdout=subprocess.DEVNULL);subprocess.run(['apt-get','install','-y','--no-install-recommends','wireguard-tools','iputils-ping','iproute2','libssl3'],env=env,check=True,stdout=subprocess.DEVNULL)"
            c.command([h['python_executable'],'-c',code],capture_output=True,timeout=self.settings.data['timeouts']['install_s'])
            c.upload(ROOT/'scripts/wan_overlay.py',helper)
            return rpc(h,'key')
        public=all_ok(hosts,install,'overlay preparation')
        # Authorize only owned peers at the configured UDP port. Keep a durable
        # intent before dispatch; identical rules are safe to replay on recovery.
        for lease in leases:
            local_ids={x['InstanceId'] for x in lease.state['instances']}
            peers=sorted(h['ssh'].split('@')[1] for h in hosts if h['instance_id'] not in local_ids)
            # Include other hosts in this regional SG too: intra-group policy is Drop.
            if len(local_ids)>1:peers=sorted(h['ssh'].split('@')[1] for h in hosts)
            intent={'peers':peers,'port':overlay['port']}
            with cloud.lease_lock(lease.path):
                lease.state=read(lease.path);lease._refresh()
                old=lease.state.get('benchmark_overlay')
                if old and old!=intent:raise ValueError('saved overlay firewall intent changed')
                lease.state['benchmark_overlay']=intent;cloud.save(lease.path,lease.state)
                m=lease.models;port=str(overlay['port'])
                permissions=[m.AuthorizeSecurityGroupRequestPermissions(ip_protocol='UDP',port_range=port+'/'+port,
                    source_cidr_ip=ip+'/32',description='Delugi exact benchmark overlay peer') for ip in peers]
                for offset in range(0,len(permissions),100):
                    lease.call('authorize_security_group',m.AuthorizeSecurityGroupRequest(region_id=lease.plan['region'],
                        security_group_id=lease.state['security_group'],permissions=permissions[offset:offset+100]))
        def configure(h):
            return rpc(h,'configure',peers=[{'replica':p['replica'],'public_ipv4':p['ssh'].split('@')[1],
                'public_key':public[p['replica']]['public_key']} for p in hosts if p['replica']!=h['replica']])
        cloud.save(self.root/'overlay.json',all_ok(hosts,configure,'overlay configuration'))
        for h in hosts:h['network_interface']=iface

    def remaining(self):
        record=self.load()
        if record is None:raise ValueError('testbed has not been created')
        if not record['leases']:return float('inf')
        return (datetime.fromisoformat(record['expires_at'].replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()

    def action(self, action):
        if action not in ('start','stop','destroy','info'):raise ValueError('unknown lifecycle action')
        self.base.mkdir(parents=True,exist_ok=True,mode=0o700)
        with cloud.lease_lock(self.base/'lifecycle'):
            if self.load() is None:return {'status':'absent'}
            if action=='info':return self.record
            results=[]
            for path in self.record['leases']:
                lease=cloud.Lease(path)
                if action=='destroy':
                    deadline=time.monotonic()+self.settings.data['timeouts']['provision_s']
                    while time.monotonic()<deadline:
                        result=lease.destroy()
                        if result.get('closed'):break
                        time.sleep(self.settings.data['timeouts']['poll_s'])
                    else:raise TimeoutError('owned deletion not confirmed; exact state retained')
                else:result=getattr(lease,action)()
                results.append(result)
            if action=='destroy':self.record.update(closed=True,status='closed')
            elif action=='stop':self.record['status']='stopped'
            elif action=='start':self.record['status']='preparing'
            self.save()
            return {'status':action,'leases':results,'external_inventory_untouched':not self.record['leases']}
