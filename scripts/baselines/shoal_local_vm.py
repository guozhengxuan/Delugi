#!/usr/bin/env python3
"""Keep the task-owned AppleHV local VM inside one live command session.

Run --create once after confirming this exact VM name is absent. Later use the
default start operation. Touch --stop-file to request a normal owned-VM stop.
No user VM, host packages, global provider config or cloud resources are changed.
"""
import argparse
import os
from pathlib import Path
import subprocess
import time

NAME='delugi-shoal-applehv-20261019'
PODMAN='/opt/podman/bin/podman'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create',action='store_true')
    parser.add_argument('--stop-file',type=Path,required=True)
    parser.add_argument('--log',type=Path,required=True)
    args=parser.parse_args()
    if args.stop_file.exists():parser.error('stop file already exists')
    root=Path(__file__).resolve().parents[2]
    env=os.environ|{'CONTAINERS_MACHINE_PROVIDER':'applehv'}
    command=[PODMAN,'machine','init','--cpus','4','--memory','16384','--swap','4096',
             '--disk-size','80','--volume',f'{root}:/workspace:rw','--volume','/private/tmp:/private/tmp:rw','--now',NAME] if args.create else [PODMAN,'machine','start',NAME]
    with args.log.open('x') as log:
        result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
        print(f'Owned VM start exit {result.returncode}',flush=True)
        if result.returncode:return result.returncode
        try:
            while not args.stop_file.exists():time.sleep(5)
        finally:
            subprocess.run([PODMAN,'machine','stop',NAME],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90)
    return 0


if __name__=='__main__':raise SystemExit(main())
