import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import wan_overlay as wan


class WanTests(unittest.TestCase):
    def test_peer_routes_are_exact_and_public_keys_only(self):
        rows = [{'replica': i, 'public_ipv4': f'8.8.8.{i}',
                 'public_key': base64.b64encode(bytes([i])*32).decode()} for i in (1, 2, 3)]
        self.assertEqual([p['overlay_ipv4'] for p in wan.peers_for(0, rows)],
                         ['10.231.0.2', '10.231.0.3', '10.231.0.4'])
        for bad in (rows[:2], [rows[0], rows[0], rows[2]],
                    [dict(rows[0], public_ipv4='0.0.0.0/0'), *rows[1:]],
                    [dict(rows[0], private_key='secret'), *rows[1:]]):
            with self.assertRaises(ValueError):
                wan.peers_for(0, bad)

    def test_timeout_uses_slowest_measured_path_and_rejects_missing_or_loss(self):
        rows = [{'source': i, 'target': j, 'rtt_ms': [240.0]*20, 'loss_percent': 0}
                for i in range(4) for j in range(4) if i != j]
        self.assertEqual(wan.timeout_from_rtt(rows)['Delta_ms'], 1000)
        rows[-1]['rtt_ms'][-1] = 801.0
        self.assertEqual(wan.timeout_from_rtt(rows)['Delta_ms'], 1300)
        with self.assertRaises(ValueError):
            wan.timeout_from_rtt(rows[:-1])
        rows[-1]['loss_percent'] = 5
        with self.assertRaises(ValueError):
            wan.timeout_from_rtt(rows)

    def test_interface_identity_is_bounded_and_non_generic(self):
        name, path = wan.identity('a'*32)
        self.assertEqual(len(name), 15)
        self.assertTrue(str(path).startswith('/run/delugi-wan-'))
        for invalid in ('', '../eth0', 'a'*31):
            with self.assertRaises(ValueError):
                wan.identity(invalid)


if __name__ == '__main__':
    unittest.main()
