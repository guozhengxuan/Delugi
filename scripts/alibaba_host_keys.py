#!/usr/bin/env python3
"""Pin new lease hosts' SSH keys through the authenticated ECS control plane.

The only guest command reads /etc/ssh/ssh_host_ed25519_key.pub. It never reads
private host keys, installs software, or changes SSH configuration.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import uuid

from alibaba_deployment import Lease, lease_lock, save

COMMAND = '#!/bin/sh\nset -eu\ncat /etc/ssh/ssh_host_ed25519_key.pub\n'


def known_hosts(instances, rows, invocation):
    expected = {i['InstanceId']: i for i in instances}
    if not expected or {r.get('InstanceId') for r in rows} != set(expected) or len(rows) != len(expected):
        raise ValueError('complete, unique results for the exact lease hosts are required')
    lines = []
    fingerprints = {}
    for row in rows:
        if row.get('InvokeId') != invocation or row.get('InvocationStatus') != 'Success' or row.get('ExitCode') != 0:
            raise ValueError('host key command did not successfully finish on every exact host')
        output = row.get('Output', '')
        if not isinstance(output,str) or len(output)>4096 or len(output.strip().splitlines())!=1:
            raise ValueError('host key response must contain one bounded public key')
        fields = output.split()
        if len(fields)<2 or fields[0]!='ssh-ed25519': raise ValueError('expected an Ed25519 public host key')
        raw = base64.b64decode(fields[1],validate=True)
        if len(raw)!=51 or raw[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
            raise ValueError('malformed SSH Ed25519 public key')
        instance = expected[row['InstanceId']]
        addresses = instance.get('PublicIpAddress',{}).get('IpAddress',[])
        if len(addresses)!=1 or ipaddress.ip_address(addresses[0]).version!=4:
            raise ValueError('one public SSH address per instance required')
        lines.append(addresses[0]+' '+fields[0]+' '+fields[1]+'\n')
        fingerprints[row['InstanceId']] = 'SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    return ''.join(sorted(lines)),fingerprints


def inspect_keys(state_path, output):
    lease = Lease(state_path)
    output = Path(output).resolve(); output.mkdir(mode=0o700,parents=True,exist_ok=True)
    with lease_lock(lease.path):
        lease.state = json.loads(lease.path.read_text())
        instances = lease._refresh()
        ids = sorted(i['InstanceId'] for i in instances)
        expected = [i for b in lease.state.get('batches',[]) for i in b.get('ids',[])]
        if not ids or set(ids)!=set(expected) or any(i['Status']!='Running' for i in instances):
            raise ValueError('every exact lease host must be Running before host authentication')
        probe = lease.state.setdefault('host_key_probe',{'client_token':str(uuid.uuid4()),'ids':ids,
                 'command_sha256':hashlib.sha256(COMMAND.encode()).hexdigest()})
        if probe['ids']!=ids or probe['command_sha256']!=hashlib.sha256(COMMAND.encode()).hexdigest():
            raise ValueError('host-key probe intent changed; retain original evidence')
        save(lease.path,lease.state)
        if 'invoke_id' not in probe:
            result = lease.call('run_command',lease.models.RunCommandRequest(region_id=lease.plan['region'],
                instance_id=ids,client_token=probe['client_token'],name='DelugiHostKeys-'+lease.state['run_id'],
                type='RunShellScript',command_content=COMMAND,content_encoding='PlainText',
                keep_command=False,timeout=30,username='root',working_dir='/tmp'))
            probe['invoke_id']=result['InvokeId']; save(lease.path,lease.state)
        result = lease.call('describe_invocation_results',lease.models.DescribeInvocationResultsRequest(
            region_id=lease.plan['region'],invoke_id=probe['invoke_id'],content_encoding='PlainText',max_results=100))
        save(output/'cloud-assistant-results.json',result)
        rows = result.get('Invocation',{}).get('InvocationResults',{}).get('InvocationResult',[])
        if result.get('Invocation',{}).get('NextToken'):
            raise ValueError('unexpected host-key result pagination')
        pending = {'Pending','Running','Scheduled','Preparing'}
        if len(rows)<len(ids) or any(row.get('InvocationStatus') in pending for row in rows):
            return {'status':'pending','invoke_id':probe['invoke_id'],'next':'repeat this command after a short delay'}
        content,prints=known_hosts(instances,rows,probe['invoke_id'])
        path=output/'known_hosts'
        if path.exists():
            if path.is_symlink() or path.read_text()!=content: raise ValueError('pinned SSH host keys changed')
        else:
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:stream.write(content)
        record={'status':'verified','method':'authenticated ECS Cloud Assistant public-host-key read',
                'invoke_id':probe['invoke_id'],'fingerprints':prints,'known_hosts':str(path),
                'sha256':hashlib.sha256(content.encode()).hexdigest()}
        save(output/'host-key-verification.json',record)
        return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    result=inspect_keys(args.state,args.output) if args.execute else {'status':'dry-run','guest_command':COMMAND,'no_api_called':True}
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'failed','error_type':type(error).__name__,'error_code':getattr(error,'code',None),
                         'message':str(error) if isinstance(error,ValueError) else 'provider operation failed; lease state retained'}))
        raise SystemExit(1)
