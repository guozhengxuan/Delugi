"""Local source/OS-state fixtures; no native Shoal validator is launched."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parent))
import shoal


class PauseObservationTests(unittest.TestCase):
    def fixture(self, *, stop_delay=3000, resume_delay=2000, timeout=10000):
        clock=[0];state={'value':'R','next':None,'start_ticks':99};signals=[]
        process=Mock(pid=43210);process.poll.return_value=None
        def now():return clock[0]
        def sleep(seconds):clock[0]+=round(seconds*1e6)
        def read(pid):
            if state['next'] is not None and clock[0]>=state['next'][0]:
                state['value']=state['next'][1];state['next']=None
            return {'pid':pid,'parent_pid':os.getpid(),'process_group':pid,'session':pid,
                    'start_ticks':state['start_ticks'],'state':state['value']}
        def send(pid,number):
            signals.append((pid,number,now()))
            delay,target=(stop_delay,'T') if number==signal.SIGSTOP else (resume_delay,'S')
            if delay is not None:state['next']=(now()+delay,target)
        pause=shoal.NativePause(process,2,[2],100000,300000,now=now,sleep=sleep,
            read_state=read,send_signal=send,ack_timeout_us=timeout)
        return pause,clock,state,signals,process

    def test_actual_stop_resume_acknowledgements_keep_requested_boundaries_separate(self):
        pause,clock,state,signals,_=self.fixture()
        clock[0]=99000;pause.tick();self.assertEqual(signals,[])
        clock[0]=107000;pause.tick()
        self.assertEqual(pause.record['status'],'stopped')
        self.assertEqual(pause.record['stop_observed_us'],110000)
        clock[0]=307000;pause.tick();pause.finish()
        row=pause.record
        self.assertEqual(row['status'],'completed')
        self.assertEqual([number for _,number,_ in signals],[signal.SIGSTOP,signal.SIGCONT])
        self.assertEqual((row['configured_start_us'],row['configured_end_us']),(100000,300000))
        self.assertEqual((row['stop_state'],row['resume_state']),('T','S'))
        self.assertEqual((row['stop_ack_us'],row['resume_ack_us']),(3000,2000))
        self.assertEqual(row['observed_stopped_interval_us'],197000)
        self.assertEqual(row['actual_interval_bounds_us'],{'lower':197000,'upper':202000})
        for name in ('stop_identity','resume_identity'):self.assertEqual(row[name],row['process_identity'])
        self.assertEqual(row['before_state'],'R')
        self.assertLessEqual(row['before_observed_us'],row['stop_sent_us'])

    def test_stop_timeout_keeps_signal_and_failure_without_invented_ack(self):
        pause,clock,_,signals,_=self.fixture(stop_delay=None,timeout=3000)
        clock[0]=100000
        with self.assertRaisesRegex(RuntimeError,'stop acknowledgement timed out'):pause.tick()
        self.assertEqual(pause.record['status'],'failed')
        self.assertEqual(signals,[(43210,signal.SIGSTOP,100000)])
        self.assertNotIn('stop_observed_us',pause.record)
        self.assertLessEqual(clock[0]-100000,4000)

    def test_resume_timeout_preserves_stopped_evidence_and_does_not_accept(self):
        pause,clock,_,signals,_=self.fixture(resume_delay=None,timeout=3000)
        clock[0]=100000;pause.tick();clock[0]=300000
        with self.assertRaisesRegex(RuntimeError,'resume acknowledgement timed out'):pause.tick()
        self.assertEqual(pause.record['status'],'failed')
        self.assertEqual(pause.record['stop_state'],'T')
        self.assertIn('resume_sent_us',pause.record)
        self.assertNotIn('resume_observed_us',pause.record)
        self.assertNotIn('actual_interval_bounds_us',pause.record)
        self.assertEqual(len(signals),2)

    def test_pid_reuse_or_unowned_session_is_rejected_before_signal(self):
        pause,clock,state,signals,_=self.fixture()
        clock[0]=100000;pause.tick();state['start_ticks']+=1;clock[0]=300000
        with self.assertRaisesRegex(RuntimeError,'identity changed'):pause.tick()
        self.assertEqual(len(signals),1)
        for field in ('pid','parent_pid','process_group','session'):
            pause,clock,_,signals,_=self.fixture();read=pause.read_state
            pause.read_state=lambda pid,field=field:read(pid)|{field:-1}
            clock[0]=100000
            with self.subTest(field=field),self.assertRaisesRegex(RuntimeError,'identity changed'):pause.tick()
            self.assertEqual(signals,[])

    def test_exited_zombie_or_already_stopped_process_is_not_a_successful_pause(self):
        for state_value in ('Z','X','T'):
            pause,clock,state,signals,_=self.fixture();state['value']=state_value;clock[0]=100000
            with self.subTest(state=state_value),self.assertRaises(RuntimeError):pause.tick()
            self.assertEqual(signals,[])
        pause,clock,_,signals,process=self.fixture();process.poll.return_value=1;clock[0]=100000
        with self.assertRaisesRegex(RuntimeError,'exited'):pause.tick()
        self.assertEqual(signals,[])

    def test_external_resume_is_detected_before_owned_continue(self):
        pause,clock,state,signals,_=self.fixture();clock[0]=100000;pause.tick()
        state['value']='R';clock[0]=300000
        with self.assertRaisesRegex(RuntimeError,'before owned SIGCONT'):pause.tick()
        self.assertEqual(len(signals),1)
        self.assertNotIn('resume_sent_us',pause.record)

    def test_signal_failure_and_exit_during_ack_preserve_failed_partial_record(self):
        pause,clock,_,_,_=self.fixture();clock[0]=100000
        pause.send_signal=Mock(side_effect=ProcessLookupError('owned child disappeared'))
        with self.assertRaises(ProcessLookupError):pause.tick()
        self.assertEqual(pause.record['status'],'failed')
        self.assertIn('stop_sent_us',pause.record)
        self.assertNotIn('stop_observed_us',pause.record)
        pause,clock,_,signals,process=self.fixture(stop_delay=None);clock[0]=100000
        process.poll.side_effect=[None,None,1]
        with self.assertRaisesRegex(RuntimeError,'exited'):pause.tick()
        self.assertEqual(pause.record['status'],'failed')
        self.assertEqual(len(signals),1)
        self.assertNotIn('stop_observed_us',pause.record)

    def test_missed_interval_and_missing_acknowledgements_fail_closed(self):
        pause,clock,_,signals,_=self.fixture();clock[0]=300000
        with self.assertRaisesRegex(RuntimeError,'missed'):pause.tick()
        self.assertEqual(signals,[])
        pause,clock,_,signals,_=self.fixture()
        with self.assertRaisesRegex(RuntimeError,'lacks complete'):pause.finish()
        self.assertEqual(pause.record['status'],'failed')
        self.assertEqual(signals,[])

    def test_fixed_fault_identity_and_ack_envelope_are_required(self):
        process=Mock(pid=123)
        for changes in ({'faulty':[]},{'end_us':100},{'ack_timeout_us':1000001}):
            values={'process':process,'replica':0,'faulty':[0],'start_us':100,'end_us':200}|changes
            with self.subTest(changes=changes),self.assertRaises(ValueError):shoal.NativePause(**values)

    def test_final_sample_resumes_across_loop_boundary(self):
        pause,clock,_,signals,_=self.fixture();clock[0]=100000;pause.tick()
        clock[0]=310000;pause.finish()
        self.assertEqual(pause.record['status'],'completed')
        self.assertEqual(pause.record['resume_sent_us'],310000)
        self.assertEqual(len(signals),2)

    def test_proc_parser_binds_pid_start_ticks_and_handles_parentheses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'123').mkdir();path=root/'123/stat'
            fields=['T',str(os.getpid()),'123','123']+['0']*15+['987654']
            path.write_text('123 (native name) with paren)) '+' '.join(fields)+'\n')
            state=shoal.linux_process_state(123,root)
            self.assertEqual(state,{'pid':123,'parent_pid':os.getpid(),'process_group':123,
                'session':123,'start_ticks':987654,'state':'T'})
            for raw in ('124 (wrong) '+' '.join(fields),'123 (short) S 1','x'*4097):
                path.write_text(raw)
                with self.subTest(raw=raw[:20]),self.assertRaises(RuntimeError):shoal.linux_process_state(123,root)


if __name__=='__main__':unittest.main()
