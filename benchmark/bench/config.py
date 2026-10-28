"""Loom/Narwhal-style deployment settings and separate bench/node parameters."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
import compact_campaign as campaign
import campaign_adapters as adapters
from evaluation_parameters import WAN_TRANSPORT


def read(path):
    return json.loads(Path(path).expanduser().read_text())


def path_at(base, value):
    p = Path(value).expanduser()
    return str((p if p.is_absolute() else base/p).resolve())


def parameters(value):
    campaign.fields(value, ('bench', 'node', 'specification'), 'benchmark parameters')
    b, n = value['bench'], value['node']
    campaign.fields(b, ('protocols','nodes','rate','tx_size','duration','drain','runs','faults','cases','fault_rate','seed'), 'bench')
    campaign.fields(n, ('Delta_ms','delay_ms','egress_mbps','batching','proposal_budget','transport','protocol_options'), 'node')
    cases = b['cases']
    if not isinstance(cases,list) or not cases or cases[0]!='healthy' or len(cases)!=len(set(cases)):
        raise ValueError('cases must start with healthy and be distinct')
    # These hooks implement one fixed faulty identity. f>1 is not silently
    # approximated by stopping one node; add the appropriate hook first.
    if type(b['faults']) is not int or b['faults'] != (1 if len(cases)>1 else 0):
        raise ValueError('supported hooks require faults=0 for healthy only or faults=1 with unfavorable cases')
    config = {'schema':1,'kind':campaign.KIND,'protocols':b['protocols'],
        'committees':b['nodes'] if isinstance(b['nodes'],list) else [b['nodes']],
        'total_honest_input_tps':b['rate'] if isinstance(b['rate'],list) else [b['rate']],
        'useful_transaction_bytes':b['tx_size'],'duration':{'warmup_s':0,'measure_s':b['duration'],'drain_s':b['drain']},
        'repeats':b['runs'],'supplemental_points_or_reruns_per_curve':0,'seed':b['seed'],
        'fault_cases':cases[1:],'fault_input_tps':b['fault_rate'],
        'network':{'added_one_way_delay_ms':n['delay_ms'],'validator_egress_mbps':n['egress_mbps']},
        'timing':{'Delta_ms':n['Delta_ms'],'mapping':'native_reviewed'},'shared_transport':n['transport'],
        'batching':n['batching'],'proposal_budget':n['proposal_budget'],
        'protocol_options':n['protocol_options'],'specification':value['specification']}
    return campaign.validate(copy.deepcopy(config))


class Settings:
    def __init__(self, filename):
        self.filename = Path(filename).expanduser().resolve()
        self.data = read(self.filename)
        campaign.fields(self.data, ('schema','loom_settings','state_directory','artifacts','testbeds',
            'ssh','ports','resources','timeouts','keep_alive'), 'deployment settings')
        if type(self.data['schema']) is not int or self.data['schema']!=1 or type(self.data['keep_alive']) is not bool:
            raise ValueError('settings schema1 and explicit keep_alive boolean required')
        for key in ('loom_settings','state_directory','artifacts'):
            self.data[key]=path_at(self.filename.parent,self.data[key])
        self.root=Path(self.data['state_directory'])
        campaign.fields(self.data['ssh'],('user','python','interface','connect_timeout_s','keepalive_s','keepalive_count'),'ssh')
        if self.data['ssh']['user']!='root':raise ValueError('current dedicated-host adapters require root')
        for key in ('connect_timeout_s','keepalive_s','keepalive_count'):
            campaign.integer(self.data['ssh'][key],1,300,key)
        campaign.fields(self.data['ports'],('consensus','control'),'ports')
        for v in self.data['ports'].values():campaign.integer(v,1024,65535,'port')
        if len(set(self.data['ports'].values()))!=2:raise ValueError('distinct consensus/control ports required')
        campaign.fields(self.data['resources'],('cpus','memory_bytes'),'resources')
        cpus=self.data['resources']['cpus']
        if not isinstance(cpus,list) or not cpus or cpus!=sorted(set(cpus)) or any(type(v)is not int or v<0 for v in cpus):
            raise ValueError('ordered distinct CPU identities required')
        campaign.integer(self.data['resources']['memory_bytes'],1,2**50,'memory bytes')
        campaign.fields(self.data['timeouts'],('provision_s','poll_s','install_s','minimum_remaining_s'),'timeouts')
        for k,v in self.data['timeouts'].items():campaign.integer(v,1,7200,k)
        if not isinstance(self.data['testbeds'],dict):raise ValueError('testbeds must be a map keyed by committee size')
        for key,t in self.data['testbeds'].items():
            if key not in ('4','10','50'):raise ValueError('unsupported committee')
            campaign.fields(t,('lease_plans','inventory','network_mode','overlay'),'testbed')
            if t['network_mode'] not in ('controlled','observed-wan-v1'):raise ValueError('unknown network mode')
            if bool(t['lease_plans'])==bool(t['inventory']):raise ValueError('choose lease plans or an existing inventory')
            if not isinstance(t['lease_plans'],list):raise ValueError('lease_plans must be a list')
            t['lease_plans']=[path_at(self.filename.parent,p) for p in t['lease_plans']]
            if t['inventory']:t['inventory']=path_at(self.filename.parent,t['inventory'])
            if t['overlay'] is not None:
                import wan_overlay
                t['overlay']=wan_overlay.settings(t['overlay'],int(key))

    def plan(self, params):
        plan=campaign.create_plan(parameters(params))
        resolved=adapters.resolve_plan(plan)
        for n in plan['config']['committees']:
            if str(n) not in self.data['testbeds']:raise ValueError(f'no saved testbed for {n} nodes')
            t=self.data['testbeds'][str(n)]
            if t['network_mode']=='observed-wan-v1' and plan['config']['network']['added_one_way_delay_ms']:
                raise ValueError('observed WAN cannot silently ignore a requested added delay')
            if t['lease_plans']:
                import alibaba_deployment as cloud
                leases=[cloud.validate_plan(read(p)) for p in t['lease_plans']]
                if sum(p['maximum_instances'] for p in leases)!=n:raise ValueError('saved regional leases must cover the exact committee')
                if len({p['region'] for p in leases})>1 and t['overlay'] is None:
                    raise ValueError('cross-region leases require the saved overlay configuration')
        return plan,resolved


def example_parameters():
    old=read(ROOT/'benchmarks/configs/compact-campaign.native-services.json')
    return {'bench':{'protocols':list(campaign.PROTOCOLS),'nodes':[4],'rate':[100],
        'tx_size':1,'duration':60,'drain':15,'runs':1,'faults':1,
        'cases':['healthy','silent-first-leader'],'fault_rate':100,'seed':1},
        'node':{'Delta_ms':1000,'delay_ms':0,'egress_mbps':20,
            'batching':{'useful_bytes_target':None,'max_wait_ms':None},
            'proposal_budget':{'useful_bytes':None,'max_payload_refs':None},
            'transport':dict(WAN_TRANSPORT),'protocol_options':{p:({} if p in ('delugi','raptr') else {'startup_seconds':10}) for p in campaign.PROTOCOLS}},
        'specification':old['specification']}


def initialize(directory, loom, lease_paths=(), inventory=None):
    """Import Loom and existing reviewed leases once; never reads access secrets."""
    import alibaba_deployment as cloud
    directory=Path(directory).expanduser().resolve();directory.mkdir(parents=True,exist_ok=True)
    if any((directory/f).exists() for f in ('settings.json','parameters.json')):
        raise ValueError('settings/parameters already exist; edit them in place')
    loom=Path(loom).expanduser().resolve();original=read(loom)
    port=original['ports']['consensus'];private=directory/'.state';private.mkdir(mode=0o700,exist_ok=True)
    # Freeze credential *paths*, not credentials; do not mutate Loom's project.
    saved=copy.deepcopy(original)
    for key in ('path','accesskey'):saved['key'][key]=path_at(loom.parent,saved['key'][key])
    cloud.save(private/'loom-settings.json',saved)
    plans=[]
    for i,source in enumerate(lease_paths):
        p=read(source);p=copy.deepcopy(p.get('plan',p));p['settings']=str(private/'loom-settings.json')
        cloud.validate_plan(p);target=private/f'regional-plan-{i}.json';cloud.save(target,p);plans.append(str(target))
    if bool(plans)==bool(inventory):raise ValueError('import saved regional leases OR an existing authenticated inventory')
    n=sum(read(p)['maximum_instances'] for p in plans) if plans else len(read(inventory)['hosts'])
    if n not in (4,10,50):raise ValueError('supported testbed sizes are 4,10,50')
    cross=len({read(p)['region'] for p in plans})>1
    data={'schema':1,'loom_settings':str(private/'loom-settings.json'),
        'state_directory':str(private),'artifacts':str(private/'artifacts.json'),
        'testbeds':{str(n):{'lease_plans':plans,'inventory':str(Path(inventory).expanduser().resolve()) if inventory else None,
            'network_mode':'observed-wan-v1' if cross else 'controlled',
            'overlay':{'nodes':n,'subnet':'10.231.0.0/24','port':51820,'mtu':1380,'keepalive_s':15} if cross else None}},
        'ssh':{'user':'root','python':'/usr/bin/python3','interface':'eth0','connect_timeout_s':60,'keepalive_s':10,'keepalive_count':3},
        'ports':{'consensus':port,'control':port+1},'resources':{'cpus':[0,1,2,3],'memory_bytes':16*2**30},
        'timeouts':{'provision_s':600,'poll_s':5,'install_s':900,'minimum_remaining_s':1800},'keep_alive':True}
    params=example_parameters();params['bench']['nodes']=[n]
    cloud.save(directory/'settings.json',data);cloud.save(directory/'parameters.json',params)
    return {'settings':str(directory/'settings.json'),'parameters':str(directory/'parameters.json'),
        'artifact_catalog':data['artifacts'],'no_cloud_calls':True,'credentials_copied':False}
