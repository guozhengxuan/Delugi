import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import campaign_adapters as adapters

class Adapters(unittest.TestCase):
    def setUp(self):self.config=json.loads((ROOT/'benchmarks/configs/compact-campaign.native-services.json').read_text())
    def test_all_native_profiles_have_identical_honest_population_and_windows(self):
        for n in (10,50):
            for p in adapters.contract.PROTOCOLS:
                r=adapters.resolve(self.config,p,n,1001)
                self.assertEqual(sum(r['allocation']['counts']),60060)
                self.assertEqual(r['effective']['duration'],{'warmup_s':0,'measure_s':60,'drain_s':15})
                self.assertEqual(r['effective']['network'],{'added_one_way_delay_ms':10,'validator_egress_mbps':100})
                self.assertEqual(r['effective']['timing']['Delta_ms'],100)
                self.assertFalse(r['comparison_eligible'])
    def test_unsupported_and_unknown_parameters_fail_instead_of_being_ignored(self):
        for p in adapters.contract.PROTOCOLS:
            for field in ('useful_bytes','max_payload_refs'):
                c=copy.deepcopy(self.config);c['proposal_budget'][field]=64
                with self.assertRaisesRegex(ValueError,'does not enforce'):adapters.resolve(c,p,50,4000)
            c=copy.deepcopy(self.config);c['protocol_options'][p]={'unknown':1}
            with self.assertRaisesRegex(ValueError,'unreviewed'):adapters.resolve(c,p,50,4000)
    def test_native_header_timeout_is_not_mislabeled_as_batch_wait(self):
        for p in ('simpleit-mempool','simpleit-dispersed'):
            r=adapters.resolve(self.config,p,50,4000)
            self.assertIsNone(r['effective']['batching']['max_wait_ms'])
            self.assertEqual(r['effective']['native_parameters']['max_header_delay'],100)
            c=copy.deepcopy(self.config);c['batching']['max_wait_ms']=5
            with self.assertRaisesRegex(ValueError,'maximum wait'):adapters.resolve(c,p,50,4000)
    def test_every_healthy_command_is_accepted_by_its_real_argument_parser(self):
        from baselines import mysticeti,autobahn
        for p in adapters.contract.PROTOCOLS:
            r=adapters.resolve(self.config,p,10,4000)
            artifact={'binary':'/fixed/node','build_receipt':'/fixed/receipt'} if p in ('delugi','raptr') else {'build_receipt':'/fixed/receipt'} if p.startswith('simpleit') else {}
            command=adapters.local_command(r,artifact,'/tmp/campaign-fixture',nodes=4,seconds=3,drain=2)
            if p in ('autobahn','mysticeti-c'):
                parser=(autobahn if p=='autobahn' else mysticeti).argument_parser()
                parsed=parser.parse_args(command[2:]);self.assertEqual(parsed.rate,4000);self.assertEqual(parsed.nodes,4)
            else:
                result=subprocess.run(command+['--help'],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
