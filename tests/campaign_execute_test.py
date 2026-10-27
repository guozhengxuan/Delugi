import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import campaign_execute as campaign


def result(rate,*,completed=True):
    population=rate*60
    count=population if completed else 0
    q={'value_ms':10 if completed else None,'status':'observed' if completed else 'censored'}
    return {'status':'completed','cohort':{'scheduled':population,'admitted':population,
        'completed':count,'unfinished':population-count,'admission_to_output':{'p50':q,'p95':q,'p99':q},
        'window':{'unique_completion_tps':rate if completed else 0,'pending_at_end':population-count,
            'stability':{'samples':[{'pending_admitted':0 if completed else population*i//10} for i in range(11)]}}}}


class Execution(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        c=json.loads((ROOT/'benchmarks/configs/compact-campaign.native-services.json').read_text())
        c.update(protocols=['delugi','raptr'],committees=[10],total_honest_input_tps=[1000,4000],protocol_options={'delugi':{},'raptr':{}})
        self.plan=campaign.contract.create_plan(c);self.events=[];self.fail=False;self.zero=False;self.crash=False;self.remaining=3600
        parent=self
        class Fake:
            def __init__(self,a,p):parent.events.append('backend')
            def acquire(self,n):parent.events.append(('acquire',n))
            def remaining(self,n):return parent.remaining
            def publish(self,n,p):parent.events.append(('publish',n,p))
            def run(self,r,p):
                parent.events.append(('run',r['protocol'],r['case'],r['effective']['total_honest_input_tps']))
                if parent.crash:raise RuntimeError('SSH connection lost after dispatch')
                p.mkdir(parents=True)
                value=({'status':'failed','error':'typed output verification failed'} if parent.fail else result(r['effective']['total_honest_input_tps'],completed=not parent.zero))
                campaign.prep.json_file(p/'result.json',value)
                return value
            def release(self,n):parent.events.append(('release',n));return {'closed':True}
        self.factory=Fake
    def run_campaign(self):
        return campaign.execute(self.plan,{},self.root/'campaign',backend_factory=self.factory,validate=lambda p,a:{'test':'no cloud'})
    def test_complete_matrix_common_fault_rate_and_repeat_is_noop(self):
        state=self.run_campaign();self.assertEqual(state['status'],'completed')
        self.assertEqual(len(state['rows']),8)
        self.assertEqual([e for e in self.events if isinstance(e,tuple) and e[0]=='acquire'],[('acquire',10)])
        faults=[r for r in state['rows'] if r['case']!='healthy']
        self.assertEqual({r['rate'] for r in faults},{1000})
        self.assertTrue((self.root/'campaign/results.csv').is_file())
        self.events.clear();self.assertEqual(self.run_campaign()['status'],'completed');self.assertEqual(self.events,['backend'])
    def test_failed_verifier_stops_sweep_and_always_deletes_owned_fleet(self):
        self.fail=True;state=self.run_campaign()
        self.assertEqual(state['status'],'failed');self.assertEqual(len(state['rows']),8)
        self.assertEqual(state['rows'][0]['status'],'failed');self.assertEqual(self.events[-1],('release',10))
        self.assertIn('typed output',state['rows'][0]['error'])
        self.assertTrue(all(r['status']=='not_run' for r in state['rows'][1:]))
        self.events.clear();self.assertEqual(self.run_campaign()['status'],'failed');self.assertEqual(self.events,['backend'])
    def test_transport_exception_keeps_failed_cell_and_ambiguous_cleanup_identity(self):
        self.crash=True;state=self.run_campaign()
        self.assertEqual(state['status'],'failed');self.assertEqual(len(state['rows']),8)
        self.assertEqual(state['rows'][0]['status'],'failed');self.assertIn('SSH connection lost',state['rows'][0]['error'])
        self.assertEqual(state['active_trial']['trial_id'],state['rows'][0]['trial_id'])
        self.events.clear()
        with self.assertRaisesRegex(RuntimeError,'no implicit rerun'):self.run_campaign()
        self.assertEqual(self.events,['backend',('release',10)])
    def test_lease_must_cover_bounded_export_and_cleanup_before_dispatch(self):
        self.remaining=1799;state=self.run_campaign()
        self.assertEqual(state['status'],'failed');self.assertEqual(len(state['rows']),8)
        self.assertTrue(all(r['status']=='not_run' for r in state['rows']))
        self.assertFalse(any(isinstance(e,tuple) and e[0]=='run' for e in self.events))
        self.assertEqual(self.events[-1],('release',10))
    def test_zero_output_is_retained_and_does_not_select_a_fault_rate(self):
        self.zero=True;state=self.run_campaign()
        self.assertEqual(state['status'],'completed_with_unrun_cells');self.assertEqual(len(state['rows']),8)
        for row in state['rows'][:4]:
            self.assertEqual(row['metrics']['goodput_tps'],0);self.assertIsNone(row['metrics']['p95_ms'])
        self.assertTrue(all(row['status']=='not_run' for row in state['rows'][4:]))
    def test_validation_failure_has_no_backend_or_cloud_side_effects(self):
        def reject(p,a):raise ValueError('stale artifact')
        with self.assertRaisesRegex(ValueError,'stale artifact'):
            campaign.execute(self.plan,{},self.root/'campaign',backend_factory=self.factory,validate=reject)
        self.assertFalse(self.events);self.assertFalse((self.root/'campaign').exists())
    def test_provider_exception_does_not_publish_signed_request_details(self):
        class ProviderError(Exception):code='AccessDenied'
        result=campaign.error_summary(ProviderError('private fixture signature in provider request'))
        self.assertIn('AccessDenied',result);self.assertNotIn('signature',result)
    def test_interrupted_trial_only_cleans_up_and_never_relaunches(self):
        state=self.run_campaign();path=self.root/'campaign/state.json'
        state['active_trial']=state['rows'][0];campaign.aliyun_bench.save(path,state);self.events.clear()
        with self.assertRaisesRegex(RuntimeError,'no implicit rerun'):self.run_campaign()
        self.assertEqual(self.events,['backend',('release',10)])
    def test_configuration_or_runtime_change_rejected_on_resume(self):
        self.run_campaign();self.events.clear()
        with self.assertRaisesRegex(ValueError,'changed'):
            campaign.execute(self.plan,{},self.root/'campaign',backend_factory=self.factory,validate=lambda p,a:{'test':'changed'})
        self.assertEqual(self.events,[])
    def test_native_settings_bind_all_roles_and_named_faults(self):
        c=json.loads((ROOT/'benchmarks/configs/compact-campaign.native-services.json').read_text())
        for p in campaign.NATIVE:
            for n in (10,50):
                for case in ('healthy','missing-data','silent-first-leader'):
                    r=campaign.adapters.resolve(c,p,n,1001,case);s=campaign.native_settings(r)
                    self.assertEqual(s['network'],{'delay_ms':10,'rate_mbps':100})
                    self.assertEqual(s['rate'],1001);self.assertEqual(s['duration'],60)
                    self.assertEqual(s['faulty'],[] if case=='healthy' else [0 if case=='missing-data' else 1])
                    if case=='silent-first-leader':self.assertEqual(s['case'],case)

if __name__=='__main__':unittest.main()
