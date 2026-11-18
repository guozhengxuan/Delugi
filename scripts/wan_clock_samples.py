#!/usr/bin/env python3
"""Sample host monotonic/UTC mappings on an existing authenticated benchmark fleet."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time

from deployment_prepare import Connection

# Linux x86-64, struct ntptimeval starts with timeval, maxerror, esterror.
# Keep storage for the remaining ABI fields. TIME_ERROR = 5 means unsynchronized.
PROBE = """
import ctypes, json, platform, subprocess, time
assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
before = time.monotonic_ns()
wall = time.time_ns()
after = time.monotonic_ns()
buf = (ctypes.c_long * 32)()
state = ctypes.CDLL(None).ntp_gettime(ctypes.byref(buf))
try:
    result = subprocess.run(['chronyc', '-c', 'tracking'], capture_output=True, timeout=2)
    tracking = result.stdout.decode().strip() if result.returncode == 0 else None
except (OSError, subprocess.TimeoutExpired):
    tracking = None
print(json.dumps(dict(before_ns=before, wall_ns=wall, after_ns=after, ntp_state=state,
    kernel_maxerror_us=buf[2], kernel_esterror_us=buf[3], chrony_tracking=tracking)))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--stop-file', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=1800)
    args = parser.parse_args()
    hosts = json.loads(args.inventory.read_text())['hosts']

    def probe(host):
        try:
            sample = Connection(host).command(
                [host['python_executable'], '-c', PROBE],
                capture_output=True, text=True, timeout=12)
            return dict(replica=host['replica'], **json.loads(sample.stdout))
        except Exception as error:
            return dict(replica=host['replica'], error=type(error).__name__)

    until = time.monotonic() + args.seconds
    with args.output.open('x') as stream, ThreadPoolExecutor(len(hosts)) as pool:
        while time.monotonic() < until and not args.stop_file.exists():
            for row in pool.map(probe, hosts):
                print(json.dumps(row), file=stream)
            stream.flush()
            for _ in range(8):
                if args.stop_file.exists():
                    return
                time.sleep(1)


if __name__ == '__main__':
    main()
