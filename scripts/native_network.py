"""Exact native protocol endpoint selection over the existing scoped netem helper."""
from __future__ import annotations
import copy
import json
from remote_deployment import RemoteDeployment


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
