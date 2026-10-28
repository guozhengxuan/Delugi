#!/usr/bin/env python3
"""Owned four-host WireGuard overlay for finite WAN functional verification.

Run over authenticated SSH on dedicated test hosts. Keys stay on their host;
only three exact peer /32 routes are installed. No NAT or default route changes.
The public UDP port must separately allow only the other leased hosts.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PORT = 51820
MTU = 1380


def identity(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('128-bit owned overlay identity required')
    return 'dgw' + nonce[:12], Path('/run/delugi-wan-' + nonce)


def address(replica):
    if type(replica) is not int or not 0 <= replica < 4:
        raise ValueError('four explicit replica identities required')
    return f'10.231.0.{replica+1}'


def peers_for(replica, peers):
    address(replica)
    if (not isinstance(peers, list) or len(peers) != 3 or
            {p.get('replica') for p in peers} != set(range(4)) - {replica}):
        raise ValueError('exactly the three other replica identities required')
    result = []
    for p in peers:
        if set(p) != {'replica', 'public_ipv4', 'public_key'}:
            raise ValueError('only public endpoint and public key may be exchanged')
        ip = ipaddress.ip_address(p['public_ipv4'])
        if ip.version != 4 or not ip.is_global:
            raise ValueError('literal public IPv4 peer required')
        if len(base64.b64decode(p['public_key'], validate=True)) != 32:
            raise ValueError('invalid WireGuard public key')
        result.append({'replica': p['replica'], 'public_ipv4': str(ip),
                       'public_key': p['public_key'], 'overlay_ipv4': address(p['replica'])})
    if len({p['public_ipv4'] for p in result}) != 3 or len({p['public_key'] for p in result}) != 3:
        raise ValueError('distinct peer endpoints and keys required')
    return sorted(result, key=lambda p: p['replica'])


def timeout_from_rtt(rows):
    """Conservative common delay-bound input; native timer multipliers remain."""
    expected = {(i, j) for i in range(4) for j in range(4) if i != j}
    if len(rows) != 12 or {(r['source'], r['target']) for r in rows} != expected:
        raise ValueError('all twelve directed paths must be measured')
    maxima = []
    for row in rows:
        samples = row['rtt_ms']
        if len(samples) < 20 or any(type(x) not in (int, float) or not math.isfinite(x) or x <= 0 for x in samples):
            raise ValueError('twenty positive RTT observations per directed path required')
        if row.get('loss_percent') != 0:
            raise ValueError('resolve calibration packet loss before choosing the timeout')
        maxima.append(max(samples))
    delta = max(100, math.ceil(1.5 * max(maxima) / 100) * 100)
    if delta > 60000:
        raise ValueError('observed path exceeds the supported timeout envelope')
    return {'Delta_ms': delta, 'maximum_observed_rtt_ms': max(maxima),
            'rule': 'ceil(1.5 * maximum observed RTT / 100 ms) * 100 ms; minimum 100 ms',
            'added_delay_ms': 0, 'native_timer_multipliers_preserved': True}


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout.strip()


def guest(request):
    if os.geteuid() != 0:
        raise ValueError('dedicated-host root required')
    action, nonce = request['action'], request['nonce']
    iface, root = identity(nonce)
    expected = {'nonce': nonce, 'replica': request['replica']}
    address(request['replica'])
    if root.exists():
        if root.is_symlink() or root.stat().st_uid != os.geteuid() or json.loads((root/'owner.json').read_text()) != expected:
            raise ValueError('overlay directory ownership differs')
    elif action == 'key':
        root.mkdir(mode=0o700)
        (root/'owner.json').write_text(json.dumps(expected))
    elif action == 'clear':
        # Missing state is not permission to delete an existing interface.
        if any(x['ifname'] == iface for x in json.loads(command(['ip', '-j', 'link', 'show']))):
            raise ValueError('interface exists without ownership evidence')
        return {'status': 'absent'}
    else:
        raise ValueError('prepare this owned overlay first')
    if action == 'key':
        key = root/'private.key'
        if key.is_symlink():
            raise ValueError('symlinked private key')
        if not key.exists():
            with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
                out.write(command(['wg', 'genkey']) + '\n')
        return {'public_key': command(['wg', 'pubkey'], input=key.read_text()),
                'replica': request['replica'], 'interface': iface}
    links = [x for x in json.loads(command(['ip', '-j', 'link', 'show'])) if x['ifname'] == iface]
    if links and links[0].get('ifalias') != 'delugi-wan:' + nonce:
        raise ValueError('interface belongs to another owner')
    if action == 'clear':
        if links:
            command(['ip', 'link', 'delete', 'dev', iface])
        shutil.rmtree(root)
        return {'status': 'removed', 'interface': iface}
    if action != 'configure':
        raise ValueError('unsupported overlay action')
    peers = peers_for(request['replica'], request['peers'])
    selected = {'peers': peers, 'MTU': MTU, 'port': PORT}
    marker = root/'configuration.json'
    if marker.exists() and json.loads(marker.read_text()) != selected:
        raise ValueError('overlay peers changed after preparation')
    marker.write_text(json.dumps(selected))
    if not links:
        command(['ip', 'link', 'add', iface, 'type', 'wireguard'])
        command(['ip', 'link', 'set', 'dev', iface, 'alias', 'delugi-wan:' + nonce])
    # wg reads the key from a file; no private key appears in process arguments.
    command(['wg', 'set', iface, 'listen-port', str(PORT), 'private-key', str(root/'private.key')])
    for p in peers:
        command(['wg', 'set', iface, 'peer', p['public_key'], 'allowed-ips', p['overlay_ipv4']+'/32',
                 'endpoint', p['public_ipv4']+':'+str(PORT), 'persistent-keepalive', '15'])
    command(['ip', 'address', 'replace', address(request['replica'])+'/32', 'dev', iface])
    command(['ip', 'link', 'set', 'dev', iface, 'mtu', str(MTU), 'up'])
    for p in peers:
        command(['ip', 'route', 'replace', p['overlay_ipv4']+'/32', 'dev', iface])
    return {'status': 'configured', 'interface': iface, 'address': address(request['replica']), **selected}


if __name__ == '__main__':
    try:
        print(json.dumps(guest(json.load(sys.stdin))))
    except Exception as error:
        # Subprocess exceptions can include commands; keys never leave the host.
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__,
                          'message': str(error) if isinstance(error, ValueError) else 'owned overlay operation failed'}))
        raise SystemExit(1)
