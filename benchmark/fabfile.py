"""One saved deployment, one parameter file: fab plan / create / remote / logs."""
from fabric import task
from bench.remote import Bench, manage
import json


def show(value):
    print(json.dumps(value,indent=2,sort_keys=True))


@task
def plan(ctx, settings='settings.json', params='parameters.json', output=None):
    """Validate and resolve all parameters offline; no SDK/SSH/provisioning."""
    result=Bench(settings,params).describe()
    if output:
        from pathlib import Path
        path=Path(output)
        with path.open('x') as stream:json.dump(result,stream,indent=2)
    show({'trials':result['plan']['trial_count'],'plan_sha256':result['plan']['plan_sha256'],
        'no_cloud_calls':True,'resolved':result['resolved'] if not output else str(path)})


@task
def create(ctx, settings='settings.json', params='parameters.json'):
    """Create or reuse the saved, budgeted testbed and authenticated host inventory."""
    show(Bench(settings,params).lifecycle('create'))


@task
def install(ctx, settings='settings.json', params='parameters.json'):
    """Verify and publish selected pinned artifacts once to the saved testbed."""
    show(Bench(settings,params).install())


@task
def remote(ctx, settings='settings.json', params='parameters.json', name=None):
    """Create/reuse, publish, run, verify and collect the entire selected matrix."""
    result=Bench(settings,params).remote(name);show(result)
    if result['status'] in ('failed','interrupted'):raise RuntimeError('benchmark failed; see retained run directory')


@task
def logs(ctx, settings='settings.json', params='parameters.json', name=None):
    """Read retained results and log/figure paths without contacting the fleet."""
    show(Bench(settings,params).logs(name))


@task
def info(ctx, settings='settings.json', params='parameters.json'):
    """Show saved exact instance ownership and lease expiry."""
    show(manage(settings,'info'))


@task
def start(ctx, settings='settings.json', params='parameters.json'):
    """Start only the exact instances belonging to this saved testbed."""
    show(manage(settings,'start'))


@task
def stop(ctx, settings='settings.json', params='parameters.json'):
    """Stop only the saved instances; disks/leases remain billable."""
    show(manage(settings,'stop'))


@task
def destroy(ctx, settings='settings.json', params='parameters.json'):
    """Delete only this testbed's instances and owned security groups."""
    show(manage(settings,'destroy'))


@task
def init(ctx, loom='../../Loom/benchmark/settings.json', lease_plans='', inventory=None, directory='.'):
    """Import Loom settings and comma-separated saved lease plans once, offline."""
    from bench.config import initialize
    show(initialize(directory,loom,[p.strip() for p in lease_plans.split(',') if p.strip()],inventory))
