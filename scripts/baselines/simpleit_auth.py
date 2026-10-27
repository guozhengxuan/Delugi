#!/usr/bin/env python3
"""Create fresh per-run mTLS identities; each replica receives only its own key.

The CA private key stays on the controller. Native public keys are supplied by
the pinned node's key generator; TLS is bound to those exact committee members.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def certificates(directory, public_keys, destinations, *, openssl='openssl'):
    root=Path(directory).resolve()
    if (len(public_keys) not in (4,10,50) or len(set(public_keys))!=len(public_keys)
            or any(not re.fullmatch('[0-9a-f]{64}',k) for k in public_keys)):
        raise ValueError('distinct32-byte native keys for4/10/50 members required')
    if set(destinations)!=set(range(len(public_keys))):
        raise ValueError('explicit per-member protocol destinations required')
    import ipaddress
    addresses=set()
    for values in destinations.values():
        if not isinstance(values,list) or not values:raise ValueError('protocol address list required')
        for a in values:
            ip,port=a.rsplit(':',1);ipaddress.IPv4Address(ip)
            if not port.isdigit() or not 1024<=int(port)<=65535 or a in addresses:
                raise ValueError('distinct unprivileged protocol ports required')
            addresses.add(a)
    root.mkdir(mode=0o700,parents=True,exist_ok=False)
    def run(*args):
        return subprocess.run([openssl,*map(str,args)],capture_output=True,check=True,timeout=30).stdout
    def new_key(path):
        run('genpkey','-algorithm','ED25519','-out',path);path.chmod(0o600)
    ca_key=root/'controller-ca.key';ca_cert=root/'ca.pem'
    new_key(ca_key)
    run('req','-new','-x509','-key',ca_key,'-out',ca_cert,'-days','2','-subj','/CN=Delugi evaluation '+os.urandom(16).hex(),
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    ext=root/'leaf-extensions.cnf'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:delugi-eval\n')
    hashes={};configs={}
    for i in range(len(public_keys)):
        d=root/f'node-{i}';d.mkdir(mode=0o700)
        new_key(d/'key.pem')
        run('req','-new','-key',d/'key.pem','-out',d/'request.csr','-subj',f'/CN=replica-{i}')
        run('x509','-req','-in',d/'request.csr','-CA',ca_cert,'-CAkey',ca_key,'-set_serial',str(i+1),
            '-out',d/'certificate.pem','-days','2','-extfile',ext)
        der=run('x509','-in',d/'certificate.pem','-outform','DER')
        hashes[i]=hashlib.sha256(der).hexdigest()
        (d/'ca.pem').write_bytes(ca_cert.read_bytes())
    members={hashes[i]:key for i,key in enumerate(public_keys)}
    destinations={a:hashes[i] for i,values in destinations.items() for a in values}
    for i in range(len(public_keys)):
        d=root/f'node-{i}'
        cfg={'schema':1,'ca_pem':str(d/'ca.pem'),'certificate_pem':str(d/'certificate.pem'),
             'private_key_pem':str(d/'key.pem'),'members':members,'destinations':destinations}
        path=d/'tls.json';path.write_text(json.dumps(cfg,indent=2)+'\n');path.chmod(0o600)
        configs[i]=path
    return {'configs':configs,'certificate_sha256':hashes,'ca_sha256':hashlib.sha256(ca_cert.read_bytes()).hexdigest()}


def replica_files(directory, replica):
    """Exactly the public trust material and this replica's secret; never CA key."""
    d=Path(directory)/f'node-{replica}'
    return {name:d/name for name in ('ca.pem','certificate.pem','key.pem','tls.json')}
