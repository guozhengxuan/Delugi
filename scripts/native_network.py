"""Exact native protocol endpoint selection over the existing scoped netem helper."""
from __future__ import annotations
import copy
import json
import timing_calibration
from remote_deployment import RemoteDeployment


def observed_wan(settings):
    """An explicit provider-capped WAN is measured, never treated as netem."""
    mode = (settings or {}).get('mode', 'controlled')
    if mode not in ('controlled', 'observed-wan-v1'):
        raise ValueError('unknown network execution mode')
    if mode == 'observed-wan-v1':
        rate = settings.get('rate_mbps')
        if (settings.get('delay_ms', 0) != 0 or settings.get('loss_percent', 0) != 0 or
                type(rate) is not int or not 1 <= rate <= 1000):
            raise ValueError('observed WAN requires zero injected delay/loss and an explicit provider bandwidth cap')
        return True
    return False


class NativeNetwork(RemoteDeployment):
    def __init__(self, plan, root, connections):
        hosts=copy.deepcopy(plan["hosts"])
        for host in hosts:
            peer=plan["endpoints"][host["replica"]]["peer"][0]
            host["advertised"]=f'{peer["ip"]}:{peer["port"]}'
            # Only the reusable network lifecycle is used; native launch/controls
            # are owned by remote_native, never by Delugi's runtime adapter.
            host["control_port"]=65000
        super().__init__({"schema":1,"hosts":hosts,"netem":plan["network"]})
        self.nonce=plan["nonce"];self.remote_directory=str(root/"controller/scripts")
        self.endpoints=plan["endpoints"];self.connections=connections
        self.aggregate=(plan.get('network') or {}).get('rate_mbps')

    def egress_rpc(self,host,request):
        reply=json.loads(self.execute(host,['sudo','-n',self.remote_python(host),self.remote_directory+'/linux_egress.py'],
            input=json.dumps(request)).stdout)
        if reply.get('ok') is not True:raise RuntimeError(reply.get('error','owned egress helper failed'))
        return reply['result']

    def configure_network(self):
        if observed_wan(self.inventory.get('netem')):
            echoes = []
            try:
                echoes = self.start_echoes('observed-wan')
                measured = self.calibrate_ring()
                self.calibration_records(measured)  # Complete raw peer/role observations.
                self.network_evidence.update(backend='observed-provider-wan-v1',
                    settings=self.inventory['netem'], observed_rtt=measured,
                    synthetic_network_changes=False, bandwidth_calibrated=False,
                    bandwidth_scope='declared provider public-egress cap; includes overlay overhead and host traffic')
                return self.network_evidence
            finally:
                self.stop_echoes(echoes)
        if self.aggregate is None:return super().configure_network()
        settings=self.inventory['netem'];echoes=[]
        try:
            echoes=self.start_echoes('before');self.network_evidence['before']=self.calibrate_ring()
            baseline=self.calibration_records(self.network_evidence['before'])
            for i,host in self.hosts.items():
                request={'action':'configure','nonce':self.nonce,'interface':host['network_interface'],
                    'peers':[p for j,other in self.hosts.items() if j!=i for p in self.protocol_endpoints(other)],
                    'local_ports':[p['port'] for p in self.protocol_endpoints(host)],
                    'delay_ms':settings.get('delay_ms',0),'rate_mbps':self.aggregate}
                self.netem_hosts.append(host)
                installed=self.egress_rpc(host,request)
                if installed.get('phase')!='active' or not installed.get('tree'):raise RuntimeError('aggregate egress installation unconfirmed')
                self.network_evidence.setdefault('configuration',{})[i]=installed
            self.network_evidence['configured']=self.calibrate_ring()
            active=self.calibration_records(self.network_evidence['configured'])
            checks=[{'source':edge[0],'destination':edge[1],'protocol_role_index':edge[2],
                **timing_calibration.addition(baseline[edge]['median'],active[edge]['median'],settings.get('delay_ms',0))} for edge in sorted(baseline)]
            self.network_evidence.update(backend='Linux_tc_aggregate_protocol_egress',settings=settings,calibration=checks,
                bandwidth_scope='one shared class per validator across all protocol peers and roles, including ACKs',
                bandwidth_calibrated=False,loaded_delay_calibrated=False)
            if not all(c['addition_matches'] for c in checks):raise RuntimeError('aggregate egress delay calibration failed')
            return self.network_evidence
        except BaseException:
            self.clear_network(verify_after=False);raise
        finally:self.stop_echoes(echoes)

    def clear_network(self,verify_after=True):
        if observed_wan(self.inventory.get('netem')):
            if self.netem_hosts:
                raise RuntimeError('observed WAN unexpectedly owns synthetic queues')
            self.network_evidence['cleanup'] = {'synthetic_network_changes': False}
            return self.network_evidence['cleanup']
        if self.aggregate is None:return super().clear_network(verify_after)
        results={};errors=[];had=bool(self.netem_hosts)
        for host in self.netem_hosts:
            try:
                self.network_evidence.setdefault('final_status',{})[host['replica']]=self.egress_rpc(host,{'action':'status','nonce':self.nonce})
            except Exception as error:self.network_evidence.setdefault('final_status_errors',{})[host['replica']]=str(error)
            try:
                result=self.egress_rpc(host,{'action':'clear','nonce':self.nonce});results[host['replica']]=result
                if result.get('phase')!='cleared' or result.get('cleanup',{}).get('restored_default') is not True:raise RuntimeError('aggregate queue restoration unconfirmed')
            except Exception as error:errors.append(str(error))
        self.network_evidence['cleanup']=results
        if errors:raise RuntimeError('; '.join(errors))
        self.netem_hosts=[]
        if verify_after and had and self.network_evidence.get('before'):
            echoes=self.start_echoes('after')
            try:
                self.network_evidence['after_cleanup']=self.calibrate_ring()
                before=self.calibration_records(self.network_evidence['before']);after=self.calibration_records(self.network_evidence['after_cleanup'])
                checks=[{'edge':edge,'restored':timing_calibration.restored(before[edge]['median'],after[edge]['median'])} for edge in before]
                self.network_evidence['cleanup_calibration']=checks
                if not all(c['restored'] for c in checks):raise RuntimeError('peer RTT failed to return to baseline')
            finally:self.stop_echoes(echoes)
        return results

    def protocol_endpoints(self,host):
        return self.endpoints[host["replica"]]["peer"]

    def execute(self,host,arguments,*,input=None,timeout=60,check=True):
        result=self.connections[host["replica"]].command(arguments,input=input,text=True,capture_output=True,timeout=timeout)
        self.commands.append({"host":host["ssh"],"arguments":arguments,"returncode":result.returncode})
        return result

    def role_addresses(self,role):
        for host in self.hosts.values():
            peer=self.protocol_endpoints(host)[role]
            host["advertised"]=f'{peer["ip"]}:{peer["port"]}'

    def start_echoes(self,phase):
        echoes=[]
        try:
            for role in range(len(self.endpoints[0]["peer"])):
                self.role_addresses(role)
                echoes+=super().start_echoes(phase+"-role"+str(role))
            return echoes
        except BaseException:
            self.stop_echoes(echoes);raise
        finally:self.role_addresses(0)

    def calibrate_ring(self):
        result=[]
        try:
            for role in range(len(self.endpoints[0]["peer"])):
                self.role_addresses(role)
                result += [dict(row,protocol_role_index=role) for row in super().calibrate_ring()]
        finally:self.role_addresses(0)
        return result
