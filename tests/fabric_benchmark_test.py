import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmark'))
from bench import config,remote,instance
from evaluation_parameters import transport,raptr_options
import campaign_adapters
import campaign_execute
import run_raptr_sustained
import wan_overlay


class FabricBenchmark(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        paper=self.root/'paper';paper.mkdir()
        (paper/'protocol').mkdir()
        files=[]
        for name in ('ordering','dissemination'):
            path=paper/'protocol'/(name+'.tex');path.write_text(name)
            files.append({'path':'protocol/'+name+'.tex','bytes':len(name),'sha256':hashlib.sha256(name.encode()).hexdigest()})
        manifest=self.root/'spec.json'
        manifest.write_text(json.dumps({'schema':2,'review_status':'reviewed','files':files}))
        self.params=config.example_parameters()
        self.params['specification']={'manifest':str(manifest),'paper_repository':str(paper)}
        self.settings={'schema':1,'loom_settings':str(self.root/'loom.json'),'state_directory':str(self.root/'state'),
            'artifacts':str(self.root/'artifacts.json'),'keep_alive':True,
            'testbeds':{'4':{'lease_plans':[],'inventory':str(self.root/'inventory.json'),'network_mode':'observed-wan-v1','overlay':None}},
            'ssh':{'user':'root','python':'/usr/bin/python3','interface':'eth0','connect_timeout_s':60,'keepalive_s':10,'keepalive_count':3},
            'ports':{'consensus':8000,'control':8001},'resources':{'cpus':[0,1,2,3],'memory_bytes':16*2**30},
            'timeouts':{'provision_s':600,'poll_s':5,'install_s':900,'minimum_remaining_s':1800}}
        self.write()

    def write(self):
        (self.root/'settings.json').write_text(json.dumps(self.settings))
        (self.root/'parameters.json').write_text(json.dumps(self.params))

    def bench(self,**kwargs):return remote.Bench(self.root/'settings.json',self.root/'parameters.json',**kwargs)

    def test_offline_twelve_runs_have_same_fixed_input_and_explicit_transport(self):
        with patch('alibaba_deployment.Lease',side_effect=AssertionError('no SDK')),patch('deployment_prepare.Connection',side_effect=AssertionError('no SSH')):
            result=self.bench().describe()
        self.assertEqual(result['plan']['trial_count'],12)
        self.assertEqual({r['total_honest_input_tps'] for r in result['plan']['trials']},{100})
        self.assertEqual({r['nodes'] for r in result['plan']['trials']},{4})
        for row in result['resolved']:
            self.assertEqual(row['allocation']['total_requests'],6000)
            if row['protocol'] in ('delugi','raptr'):
                self.assertEqual(row['effective']['transport']['connect_timeout_ms'],5000)

    def test_parameter_changes_change_every_protocol_and_the_plan_identity(self):
        before=self.bench().plan['plan_sha256']
        self.params['bench'].update(rate=[123],fault_rate=123,tx_size=7,duration=7,runs=2)
        self.params['node']['Delta_ms']=800
        self.params['node']['transport']['connect_timeout_ms']=12345
        self.write();result=self.bench().describe()
        self.assertNotEqual(result['plan']['plan_sha256'],before)
        self.assertEqual(result['plan']['trial_count'],24)
        for row in result['resolved']:
            self.assertEqual(row['allocation']['total_requests'],861)
            self.assertEqual(row['effective']['timing']['Delta_ms'],800)
            if row['protocol'] in ('delugi','raptr'):
                self.assertEqual(row['effective']['transport']['connect_timeout_ms'],12345)
            else:
                self.assertEqual(campaign_execute.native_settings(row)['duration'],7)

    def test_typo_unsupported_fault_count_and_silently_ignored_delay_fail_offline(self):
        for mutation in (lambda p:p['node']['transport'].update(connect_timout_ms=2),
                         lambda p:p['bench'].update(faults=2),lambda p:p['node'].update(delay_ms=10),
                         lambda p:p['node']['proposal_budget'].update(max_payload_refs=8),
                         lambda p:p['node']['protocol_options']['simpleit-mempool'].update(batching={'max_wait_ms':5})):
            original=copy.deepcopy(self.params);mutation(self.params);self.write()
            with self.assertRaises(ValueError):self.bench()
            self.params=original

    def test_raptr_generated_config_and_real_cli_receive_overrides(self):
        self.params['node']['protocol_options']['raptr']={'transport':{'connect_timeout_ms':9000},
            'quorum_store':{'sender_max_batch_txns':100},'limits':{'ingress_capacity':2000},
            'latency_trace':{'max_events':100000}}
        self.write();row=next(r for r in self.bench().resolved if r['protocol']=='raptr')
        e=row['effective']
        cfg=run_raptr_sustained.make_config(self.root,nodes=4,addresses=[f'127.0.0.1:{20000+i}' for i in range(4)],transport=e['transport'],node_options=e['node_options'])
        self.assertEqual(cfg['transport']['connect_timeout_ms'],9000)
        self.assertEqual(cfg['quorum_store']['sender_max_batch_txns'],100)
        self.assertEqual(cfg['limits']['ingress_capacity'],2000)
        self.assertEqual(cfg['latency_trace'], {'max_events':100000})
        command=campaign_adapters.local_command(row,{'binary':'/node','build_receipt':'/receipt'},self.root/'trial')
        actual=json.loads(command[command.index('--transport-json')+1])
        self.assertEqual(actual,cfg['transport'])
        self.assertEqual(json.loads(command[command.index('--node-options-json')+1])['latency_trace'],
                         cfg['latency_trace'])
        with self.assertRaises(ValueError):raptr_options({'quorum_store':{'batch_sze':100}})
        with self.assertRaises(ValueError):transport({'connect_timeout_ms':True})

    def test_remote_resume_is_noop_changed_params_reuse_fleet_and_fixed_fault_runs_survive_zero_output(self):
        events=[];parent=self;fleet=self.root/'fleet';fleet.mkdir()
        (self.root/'artifacts.json').write_text(json.dumps({'common':{'publication':str(self.root/'publication.json'),'local_verifier':{}}}))
        (self.root/'publication.json').write_text(json.dumps({'archive':'/fixture','sha256':'a','binary_sha256':'b'}))
        self.params['bench']['protocols']=['delugi','raptr']
        self.params['node']['protocol_options']={p:{} for p in ('delugi','raptr')};self.write()
        class Manager:
            def __init__(self,settings,nodes):self.root=fleet
            def create(self):events.append('acquire');return {'hosts':[]}
            def remaining(self):return 3600
            def action(self,action):events.append(action);return {'closed':True}
        def publish(inventory,archive,sha,binary,out,**kw):
            events.append('publish');out.mkdir(parents=True)
            record={'status':'published','hosts':[]};(out/'inventory.json').write_text(json.dumps(record));return record
        def run(resolved,*args,**kwargs):
            events.append(('run',resolved['protocol'],resolved['case'],resolved['effective']['total_honest_input_tps']))
            # Successful execution with no completed requests must still run the
            # explicitly selected fault-rate cell; no frontier selection here.
            return {'status':'completed'}
        with patch.object(remote.Bench,'validate',return_value={'common':{'fixture':'binding'}}),patch('aliyun_bench.publish',side_effect=publish),patch('common_sustained_remote.run_delugi',side_effect=run),patch('common_sustained_remote.run_raptr',side_effect=run),patch('campaign_plot.render',return_value={}):
            b=self.bench(manager_factory=Manager)
            r=b.remote();self.assertEqual(r['status'],'completed')
            self.assertEqual(len([e for e in events if isinstance(e,tuple)]),4)
            self.assertEqual(events.count('publish'),1)
            before=list(events);self.assertEqual(b.remote()['status'],'completed');self.assertEqual(events,before)
            self.params['bench'].update(rate=[200],fault_rate=200);self.write()
            r2=self.bench(manager_factory=Manager).remote();self.assertNotEqual(r['output'],r2['output'])
            self.assertEqual(events.count('publish'),1)
            self.assertNotIn('destroy',events)

    def test_failed_artifact_check_has_no_cloud_or_host_side_effect(self):
        with patch.object(remote.Bench,'validate',side_effect=ValueError('stale build')),patch.object(instance.InstanceManager,'create') as create:
            with self.assertRaisesRegex(ValueError,'stale'):self.bench().remote()
            create.assert_not_called()

    def test_failed_run_destroys_exact_fleet_even_when_keep_alive(self):
        events=[]
        class Manager:
            def __init__(self,s,n):pass
            def action(self,action):events.append(action);return {'closed':True}
        (self.root/'artifacts.json').write_text('{}')
        b=remote.Backend(config.Settings(self.root/'settings.json'),{'catalog':str(self.root/'artifacts.json')},self.root,manager_factory=Manager)
        b.managers[4]=Manager(None,4);b.failed=True
        b.release(4);self.assertEqual(events,['destroy'])
        events.clear();b.managers={};b.failed=False;b.release(4);self.assertEqual(events,['destroy'])

    def test_cleanup_ignores_invalid_workload_and_controller_lock_prevents_overlap(self):
        self.params['bench']['rate']='broken'
        self.write()
        # No existing fleet: no provider is instantiated during cleanup.
        with patch('alibaba_deployment.Lease',side_effect=AssertionError('no provider')):
            self.assertEqual(remote.manage(self.root/'settings.json','destroy'),{'4':{'status':'absent'}})
        with remote.cloud.lease_lock(self.root/'state'/'dispatch'):
            with self.assertRaisesRegex(ValueError,'another lease action'):
                remote.manage(self.root/'settings.json','stop')

    def test_configurable_lease_keeps_the_same_aggregate_budget_guard(self):
        from alibaba_deployment import validate_plan,Lease
        from campaign_budget import Ledger
        ledger=Ledger(self.root/'budget.json');ledger.initialize(5000,'a'*64)
        p={'schema':1,'profile':'configured-evaluation-v1','maximum_instances':4,
            'lifetime_hours':1,'budget_cny':30,'hourly_quote_cny':2,'cost_margin_cny':5,
            'internet_charge_type':'PayByBandwidth','internet_max_bandwidth_out':100,
            'controller_cidr':'192.0.2.10/32','instance_type':'ecs.g9i.xlarge','system_disk_gib':120,
            'user_authorization':'fixture','peer_port_ranges':['18000/18001'],
            'campaign_budget':{'path':str(ledger.path),'authorization_sha256':'a'*64}}
        validate_plan(p)
        lease=object.__new__(Lease);lease.plan=p;lease.state={'run_id':'fixture-1'}
        lease._reserve_campaign(4)
        self.assertEqual(ledger.snapshot()['reserved_fen'],3000)
        lease.state={'run_id':'fixture-2'}
        with self.assertRaisesRegex(ValueError,'remaining aggregate'):lease._reserve_campaign(4)
        for key,value in [('internet_max_bandwidth_out',True),('peer_port_ranges',['22/65535']),('system_disk_gib',0)]:
            with self.assertRaises(ValueError):validate_plan(dict(p,**{key:value}))

    def test_initialize_reads_credential_paths_only_and_preserves_loom(self):
        loom={'key':{'path':'ssh-key','accesskey':'absent-secret.json','name':'test-key'},
            'ports':{'consensus':12000},'instances':{'type':'ecs.g9i.xlarge','regions':['region']}}
        source=self.root/'loom-source.json';source.write_text(json.dumps(loom))
        inventory=self.root/'external.json';inventory.write_text(json.dumps({'hosts':[{}]*4}))
        out=self.root/'imported'
        result=config.initialize(out,source,inventory=inventory)
        self.assertTrue(result['no_cloud_calls']);self.assertFalse(result['credentials_copied'])
        self.assertEqual(json.loads(source.read_text()),loom)
        imported=config.read(out/'settings.json');self.assertEqual(imported['ports']['consensus'],12000)
        paths=config.read(out/'.state/loom-settings.json')
        self.assertEqual(paths['key']['accesskey'],str((self.root/'absent-secret.json').resolve()))
        with self.assertRaisesRegex(ValueError,'already exist'):config.initialize(out,source,inventory=inventory)

    def test_protocol_selection_reuses_other_saved_native_options(self):
        self.params['bench']['protocols']=['delugi','raptr'];self.write()
        result=self.bench().describe()
        self.assertEqual(result['plan']['trial_count'],4)
        self.assertEqual(set(result['plan']['config']['protocol_options']),{'delugi','raptr'})
        # Original settings retain the native options for a later selection.
        self.assertIn('mysticeti-c',self.params['node']['protocol_options'])

    def test_larger_transaction_size_derives_bounded_delugi_defaults(self):
        self.params['bench']['tx_size']=4096;self.write()
        e=next(r['effective'] for r in self.bench().resolved if r['protocol']=='delugi')
        self.assertLessEqual(e['batching']['max_transactions']*(4096+60)+8,256*1024)
        self.assertLessEqual(e['arrival_queue_capacity']*(4096+60),64*1024**2)
        self.params['node']['protocol_options']['delugi']={'arrival_queue_capacity':65536};self.write()
        with self.assertRaisesRegex(ValueError,'64MiB'):self.bench()

    def test_overlay_and_ssh_configuration_enforce_units_and_committee(self):
        from remote_deployment import ssh_arguments
        c=wan_overlay.settings({'subnet':'10.240.0.0/24','port':52999,'mtu':1280,'keepalive_s':9},10)
        self.assertEqual(wan_overlay.address(9,c),'10.240.0.10')
        with self.assertRaises(ValueError):wan_overlay.settings({'subnet':'0.0.0.0/0'},4)
        command=ssh_arguments({'known_hosts_file':'/keys','identity_file':'/identity','ssh_connect_timeout_s':70})
        self.assertIn('ConnectTimeout=70',command)
        with self.assertRaises(ValueError):ssh_arguments({'ssh_connect_timeout_s':False})


if __name__=='__main__':unittest.main()
