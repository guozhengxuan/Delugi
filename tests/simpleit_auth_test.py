import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/baselines'))
import simpleit_auth


class CertificateTests(unittest.TestCase):
    def test_per_replica_secrets_and_fresh_run_binding(self):
        with tempfile.TemporaryDirectory() as t:
            keys=[f'{i+1:064x}' for i in range(4)]
            addresses={i:[f'127.0.0.1:{17000+i}'] for i in range(4)}
            a=simpleit_auth.certificates(Path(t)/'a',keys,addresses)
            b=simpleit_auth.certificates(Path(t)/'b',keys,addresses)
            self.assertNotEqual(a['ca_sha256'],b['ca_sha256'])
            self.assertFalse(set(a['certificate_sha256'].values())&set(b['certificate_sha256'].values()))
            for i in range(4):
                files=simpleit_auth.replica_files(Path(t)/'a',i)
                self.assertEqual(set(files),{'key.pem','certificate.pem','ca.pem','tls.json'})
                self.assertEqual(files['key.pem'].stat().st_mode&0o777,0o600)
                cfg=json.loads(files['tls.json'].read_text())
                self.assertEqual(cfg['members'][a['certificate_sha256'][i]],keys[i])


@unittest.skipUnless(os.environ.get('SIMPLEIT_TLS_PROBE'),'requires the compiled pinned native TLS probe')
class LiveChannelTests(unittest.TestCase):
    def test_authenticated_channels_spoof_and_cross_run_replay(self):
        with tempfile.TemporaryDirectory() as t:
            keys=[f'{i+1:064x}' for i in range(4)]
            with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            addresses={i:[f'127.0.0.1:{port+i}'] for i in range(4)}
            a=simpleit_auth.certificates(Path(t)/'a',keys,addresses)
            b=simpleit_auth.certificates(Path(t)/'b',keys,addresses)
            def case(client,claimed,success):
                env=os.environ|{'DELUGI_SIMPLEIT_TLS':str(a['configs'][0])}
                server=subprocess.Popen([os.environ['SIMPLEIT_TLS_PROBE'],'server',addresses[0][0]],env=env,
                                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    self.assertTrue(select.select([server.stdout],[],[],5)[0],'server readiness timeout')
                    self.assertEqual(server.stdout.readline().strip(),'ready')
                    result=subprocess.run([os.environ['SIMPLEIT_TLS_PROBE'],'client',addresses[0][0],claimed],
                        env=os.environ|{'DELUGI_SIMPLEIT_TLS':str(client)},capture_output=True,text=True,timeout=10)
                    server.communicate(timeout=10)
                    self.assertEqual(result.returncode==0,success,result.stderr)
                    self.assertEqual(server.returncode==0,success)
                finally:
                    if server.poll() is None:server.kill();server.communicate(timeout=5)
            case(a['configs'][1],keys[1],True)
            case(a['configs'][1],keys[2],False)
            case(b['configs'][1],keys[1],False)
            bad=json.loads(a['configs'][1].read_text())
            bad['destinations'][addresses[0][0]]=a['certificate_sha256'][2]
            changed=Path(t)/'wrong-destination.json';changed.write_text(json.dumps(bad))
            case(changed,keys[1],False)


if __name__=='__main__':unittest.main()
