import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from alibaba_host_keys import known_hosts


class HostKeyTests(unittest.TestCase):
    def setUp(self):
        self.instances=[{'InstanceId':'i-owned','PublicIpAddress':{'IpAddress':['192.0.2.1']}}]
        raw=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'a'*32
        self.row={'InstanceId':'i-owned','InvokeId':'t-owned','InvocationStatus':'Success','ExitCode':0,
                  'Output':'ssh-ed25519 '+base64.b64encode(raw).decode()+' root@node\n'}

    def test_authenticated_output_pins_only_exact_host_and_key(self):
        content,prints=known_hosts(self.instances,[self.row],'t-owned')
        self.assertTrue(content.startswith('192.0.2.1 ssh-ed25519 '))
        self.assertTrue(prints['i-owned'].startswith('SHA256:'))
        self.assertNotIn('root@',content)

    def test_wrong_identity_status_or_output_cannot_be_pinned(self):
        for change in ({'InstanceId':'i-other'},{'InvokeId':'t-other'},{'InvocationStatus':'Running'},
                       {'ExitCode':1},{'Output':self.row['Output']*2},{'Output':'ssh-ed25519 invalid'}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                known_hosts(self.instances,[dict(self.row,**change)],'t-owned')
        with self.assertRaises(ValueError):known_hosts(self.instances,[self.row,self.row],'t-owned')
        with self.assertRaises(ValueError):known_hosts(self.instances,[],'t-owned')


if __name__=='__main__':unittest.main()
