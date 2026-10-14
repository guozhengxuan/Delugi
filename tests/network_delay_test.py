import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

HELPER = module('dummynet_helper')
CLIENT = module('network_delay')

class FakeShaper(HELPER.Shaper):
    def __init__(self, directory):
        super().__init__(directory)
        self.pipes = [60000, 60001]
        self.live = set()
        self.calls = []
        self.fail_config = None
        self.fail_clear = False
    def run(self, argv, text=None, check=True):
        self.calls.append((argv, text))
        if argv == [HELPER.DNCTL, 'list']:
            return ''.join(f'{p:05d}: unlimited 10 ms\n' for p in self.live)
        if 'config' in argv:
            if int(argv[2]) == self.fail_config:
                raise RuntimeError('injected pipe failure')
            self.live.add(int(argv[2]))
        if argv[1:3] == ['pipe', 'delete']:
            self.live.discard(int(argv[3]))
        if argv[0] == HELPER.PFCTL and '-n' not in argv and text == '' and self.fail_clear:
            raise RuntimeError('injected anchor clear failure')
        return ''

class NetworkDelayTests(unittest.TestCase):
    def test_invalid_scope_rejected_before_kernel_mutation(self):
        for protocol, ports, delay in [('shell', [5000], 10), ('delugi', [22], 10),
                                      ('raptr', [True], 10), ('mysticeti', [5000], 0),
                                      ('delugi', [5000], True), ('delugi', [], 10)]:
            with self.subTest(protocol=protocol, ports=ports, delay=delay):
                with self.assertRaises(ValueError):
                    HELPER.validate_request(protocol, ports, delay)
    def test_rules_scope_is_only_selected_ipv4_loopback_tcp_ports(self):
        rules = HELPER.rules_for([5000, 5001], [60000, 60001])
        self.assertEqual(len(rules.splitlines()), 2)
        for line in rules.splitlines():
            self.assertIn('out quick on lo0 inet proto tcp', line)
            self.assertIn('from 127.0.0.1', line)
            self.assertIn('to 127.0.0.1', line)
            self.assertIn('port { 5000, 5001 }', line)
    def test_partial_config_rolls_back_only_created_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            shaper = FakeShaper(Path(directory))
            shaper.fail_config = 60001
            with self.assertRaisesRegex(RuntimeError, 'injected pipe'):
                shaper.configure('delugi', [5000], 10)
            self.assertEqual(shaper.live, set())
            self.assertIsNone(shaper.active)
            self.assertEqual(shaper.created_pipes, set())
    def test_cleanup_retains_pipes_until_anchor_removal_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            shaper = FakeShaper(Path(directory))
            shaper.configure('raptr', [5000], 10)
            shaper.fail_clear = True
            with self.assertRaisesRegex(RuntimeError, 'anchor clear'):
                shaper.clear()
            self.assertEqual(shaper.live, {60000, 60001})
            self.assertTrue(shaper.anchor_loaded)
            with self.assertRaisesRegex(RuntimeError, 'another trial'):
                shaper.configure('raptr', [5000], 10)
            shaper.fail_clear = False
            shaper.clear()
            self.assertIsNone(shaper.active)
    def test_cleanup_deletes_both_owned_pipes_despite_incomplete_list(self):
        with tempfile.TemporaryDirectory() as directory:
            shaper = FakeShaper(Path(directory))
            shaper.configure('delugi', [5000], 10)
            original = shaper.run
            def incomplete(argv, text=None, check=True):
                if argv == [HELPER.DNCTL, 'list']:
                    return '60000: unlimited 10 ms\n'
                return original(argv, text, check)
            shaper.run = incomplete
            evidence = shaper.clear()
            self.assertFalse(shaper.live)
            self.assertEqual(set(evidence['pipes']), {'60000', '60001'})

    def test_pipe_collision_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            shaper = FakeShaper(Path(directory))
            shaper.live.add(60000)
            with self.assertRaisesRegex(RuntimeError, 'claimed'):
                shaper.configure('delugi', [5000], 10)
            self.assertFalse(any('config' in argv for argv, _ in shaper.calls))
    def test_no_env_is_noop_partial_env_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(CLIENT.configure_from_environment('delugi', [5000]))
            self.assertIsNone(CLIENT.clear_from_environment())
        for environment in ({'DELUGI_NETWORK_DELAY_MS': '10'}, {'DELUGI_SHAPER_CONTROL': '/missing'}):
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(RuntimeError):
                    CLIENT.configure_from_environment('delugi', [5000])
    def test_prepare_uses_private_capability_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / 'control'
            environment = CLIENT.prepare(directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            token = Path(environment['DELUGI_SHAPER_TOKEN_FILE'])
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(token.read_text().strip()), 64)
            with self.assertRaises(FileExistsError):
                CLIENT.prepare(directory)
    def test_shutdown_releases_own_pf_reference_after_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            shaper = FakeShaper(Path(directory))
            shaper.reference = '12345'
            shaper.configure('delugi', [5000], 10)
            shaper.fail_clear = True
            self.assertTrue(shaper.shutdown())
            self.assertIn(([HELPER.PFCTL, '-X', '12345'], None), shaper.calls)
            self.assertIsNone(shaper.reference)

if __name__ == '__main__':
    unittest.main()
