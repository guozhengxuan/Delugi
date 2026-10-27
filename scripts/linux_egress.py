#!/usr/bin/env python3
"""Owned aggregate protocol-egress HTB/netem profile for dedicated Linux VMs.

All selected peers/roles share ONE rate class. ACKs are selected by local source
port, outbound connections by remote destination port. SSH uses the unshaped
default class. This profile changes a pristine default root only; it refuses
existing custom queues/filters and verifies exact ownership before cleanup.
Calibration is separate: installing a nominal rate/delay is not qualification.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import time
import linux_netem as base

KIND = 'delugi-linux-egress-v1'
ROOT = Path('/run/delugi-egress')


def validate_request(value):
    if not isinstance(value, dict): raise base.NetemError('object required')
    extra = set(value) - {'action', 'nonce', 'interface', 'peers', 'local_ports',
                          'delay_ms', 'rate_mbps', 'queue_packets', 'burst_bytes'}
    if extra: raise base.NetemError('unknown egress field')
    original = {k:v for k,v in value.items() if k not in ('rate_mbps', 'queue_packets', 'burst_bytes')}
    parsed = base.validate_request(original)
    if parsed['action'] != 'configure':
        if set(value) != {'action', 'nonce'}: raise base.NetemError('status/clear only takes run identity')
        return parsed
    for key, low, high, default in [('rate_mbps',1,1000,None), ('queue_packets',1,10000,10000),
                                   ('burst_bytes',1514,1048576,65536)]:
        v = value.get(key, default)
        if type(v) is not int or not low <= v <= high: raise base.NetemError('invalid '+key)
        parsed[key] = v
    parsed.pop('loss_percent')
    return parsed


def commands(config, major):
    """A single aggregate class; peer count never multiplies bandwidth."""
    dev, root, group = config['interface'], f'{major:x}:', f'{major:x}:10'
    burst, rate = str(config['burst_bytes']), str(config['rate_mbps'])+'mbit'
    result = [
        ['tc','qdisc','replace','dev',dev,'root','handle',root,'htb','default','1'],
        ['tc','class','add','dev',dev,'parent',root,'classid',f'{major:x}:1','htb','rate','100gbit','ceil','100gbit'],
        ['tc','class','add','dev',dev,'parent',root,'classid',group,'htb','rate',rate,'ceil',rate,'burst',burst,'cburst',burst],
        ['tc','qdisc','add','dev',dev,'parent',group,'handle',f'{major+1:x}:','netem',
         'delay',str(config['delay_ms'])+'ms','limit',str(config['queue_packets'])],
    ]
    matches = {(p['ip'], 'dst_port', p['port']) for p in config['peers']}
    matches |= {(p['ip'], 'src_port', port) for p in config['peers'] for port in config['local_ports']}
    for pref, (ip, field, port) in enumerate(sorted(matches), 1000):
        result.append(['tc','filter','add','dev',dev,'parent',root,'protocol','ip','pref',str(pref),
                       'flower','skip_hw','dst_ip',ip+'/32','ip_proto','tcp',field,str(port),'classid',group])
    return result


def static(rows):
    """Strip counters only; retain queue/class/filter configuration for ownership."""
    ignored = {'bytes','packets','drops','overlimits','requeues','backlog','qlen','stats',
               'stats2','xstats','used','lastuse','refcnt','direct_packets_stat'}
    if isinstance(rows, list): return [static(r) for r in rows]
    if isinstance(rows, dict): return {k:static(v) for k,v in rows.items() if k not in ignored}
    return rows


class Controller(base.Controller):
    def __init__(self, state_root=ROOT, run=base.command): super().__init__(state_root, run)

    def _load(self, nonce):
        path=self.root/nonce/'state.json'
        if not path.exists(): return None
        if path.is_symlink() or path.parent.is_symlink(): raise base.NetemError('symlinked state')
        v=json.loads(path.read_text())
        if v.get('nonce')!=nonce or v.get('schema')!=KIND: raise base.NetemError('run identity changed')
        return v

    def _tree(self, state):
        dev=state['config']['interface']; parent=f"{state['major']:x}:"
        return {'qdiscs':self._qdiscs(dev),
                'classes':self._json(['tc','-s','-j','class','show','dev',dev]),
                'filters':self._json(['tc','-s','-j','filter','show','dev',dev,'parent',parent])}

    def _physical(self, state):
        links=self._links()
        link=next((r for r in links if r['ifname']==state['config']['interface']),None)
        if link is None or link['ifindex']!=state['ifindex']: raise base.NetemError('interface identity changed')

    def _assert_owned(self, state, tree):
        self._physical(state)
        root=next((r for r in tree['qdiscs'] if r.get('root')),None)
        if root is None or root.get('kind')!='htb' or root.get('handle')!=f"{state['major']:x}:":
            raise base.NetemError('root no longer belongs to this run')
        if 'tree' in state and static(tree)!=state['tree']:
            raise base.NetemError('owned egress configuration changed; cleanup refused')

    def dispatch(self, request):
        request=validate_request(request)
        with self._lock():
            state=self._load(request['nonce'])
            if request['action']=='configure':
                config={k:v for k,v in request.items() if k!='action'}
                if state:
                    if state['config']!=config: raise base.NetemError('run configuration changed')
                    if state['phase']!='active': raise base.NetemError('partial/closed run; clear before a new identity')
                    tree=self._tree(state);self._assert_owned(state,tree)
                    return {'phase':'active','tree':tree,'calibrated':False}
                dev=config['interface'];links=self._links()
                link=next((r for r in links if r['ifname']==dev),None)
                if link is None: raise base.NetemError('interface absent')
                before=self._qdiscs(dev)
                # Linux reinstalls its default root when the temporary root is
                # deleted. Never replace a custom user root or any clsact hook.
                if not before or any(r.get('handle')!='0:' or r.get('kind') not in ('mq','fq_codel','pfifo_fast','noqueue') for r in before):
                    raise base.NetemError('dedicated pristine default interface required')
                major=0x8000+(int(config['nonce'][:4],16)%0x3ffe)*2
                state={'schema':KIND,'nonce':config['nonce'],'config':config,'ifindex':link['ifindex'],
                       'major':major,'phase':'installing','before':static(before),'attempted':0}
                self._save(state)
                for index, command in enumerate(commands(config,major)):
                    state['attempted']=index+1;self._save(state)
                    self.run(command)
                    # Persist each confirmed prefix so a later failed command
                    # can be cleaned without inventing a completed install.
                    state['tree']=static(self._tree(state));self._save(state)
                tree=self._tree(state); self._assert_owned(state,tree)
                state.update(phase='active',tree=static(tree));self._save(state)
                return {'phase':'active','tree':tree,'calibrated':False,
                        'scope':'one aggregate protocol egress class including TCP ACKs; SSH/default class excluded'}
            if state is None: return {'phase':'absent','mutated':False}
            if state['phase']=='cleared': return {'phase':'cleared','cleanup':state['cleanup']}
            tree=self._tree(state)
            if request['action']=='status':
                self._assert_owned(state,tree)
                return {'phase':state['phase'],'tree':tree,'calibrated':False}
            self._physical(state)
            # A command may fail before the root replacement. Do not delete the
            # original root, and do not claim cleanup if an unrelated root won.
            if static(tree['qdiscs'])==state['before'] and not tree['classes'] and not tree['filters']:
                pass
            else:
                self._assert_owned(state,tree)
                if 'tree' not in state:
                    # Partial installation is retained for explicit reconciliation:
                    # no complete structural ownership receipt was obtained.
                    raise base.NetemError('partial installation needs structural reconciliation')
                state['final_tree']=tree;state['phase']='clearing';self._save(state)
                self.run(['tc','qdisc','del','dev',state['config']['interface'],'root','handle',f"{state['major']:x}:"])
            restored=self._qdiscs(state['config']['interface'])
            if static(restored)!=state['before']: raise base.NetemError('default queue restoration differs')
            state.update(phase='cleared',cleanup={'restored_default':True,'final_tree':state.get('final_tree'),
                                                'cleared_unix':time.time()})
            self._save(state)
            return {'phase':'cleared','cleanup':state['cleanup']}


def main():
    try:
        if sys.platform!='linux' or os.geteuid()!=0: raise base.NetemError('root Linux helper required')
        raw=sys.stdin.buffer.read(base.MAX_REQUEST_BYTES+1)
        if len(raw)>base.MAX_REQUEST_BYTES: raise base.NetemError('request too large')
        print(json.dumps({'ok':True,'result':Controller().dispatch(json.loads(raw))}))
        return 0
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e)}));return 1

if __name__=='__main__': raise SystemExit(main())
