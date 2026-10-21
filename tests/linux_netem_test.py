"""Unprivileged ownership/scope tests; live RTT calibration is a separate gate."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import linux_netem as netem


NONCE = "0123456789abcdef0123456789abcdef"


def request(**changes):
    value = {"action": "configure", "nonce": NONCE, "interface": "eth0",
             "peers": [{"ip": "10.1.2.3", "port": 9000}], "local_ports": [9001],
             "delay_ms": 10, "loss_percent": 0}
    value.update(changes)
    return value


class Kernel:
    """Small stateful iproute2 fake, including tc's summary-only filter rows."""
    def __init__(self, existing_hook=False):
        self.links = [{"ifindex": 2, "ifname": "eth0", "mtu": 1500}]
        self.qdiscs = {"eth0": [{"kind": "fq_codel", "handle": "0:", "root": True,
                                 "options": {"limit": 10240}, "bytes": 19}]}
        if existing_hook:
            self.qdiscs["eth0"].append({"kind": "clsact", "handle": "ffff:", "parent": "ffff:fff1"})
        self.filters = {"ingress": [], "egress": []}
        self.commands = []
        self.mutations = []
        self.fail = None

    def run(self, args):
        self.commands.append(args[:])
        if args == ["ip", "-j", "-d", "link", "show"]:
            return json.dumps(self.links)
        if args[:5] == ["tc", "-s", "-j", "qdisc", "show"]:
            return json.dumps(self.qdiscs.get(args[6], []))
        if args[:5] == ["tc", "-s", "-j", "filter", "show"]:
            rows = self.filters[args[7]]
            summaries = [{key: row[key] for key in ("pref", "kind", "protocol") if key in row}
                         for row in rows]
            return json.dumps(summaries + rows)
        self.mutations.append(args[:])
        if self.fail and self.fail(args):
            self.fail = None
            raise netem.NetemError("injected command failure")
        if args[:4] == ["ip", "link", "add", "name"]:
            name = args[4]
            if any(link["ifname"] == name for link in self.links):
                raise netem.NetemError("link exists")
            self.links.append({"ifindex": 50, "ifname": name, "linkinfo": {"info_kind": "ifb"}})
            self.qdiscs[name] = [{"kind": "noqueue", "handle": "0:", "root": True}]
        elif args[:4] == ["ip", "link", "set", "dev"]:
            link = next(link for link in self.links if link["ifname"] == args[4])
            if args[5] == "alias":
                link["ifalias"] = args[6]
        elif args[:4] == ["ip", "link", "del", "dev"]:
            self.links = [link for link in self.links if link["ifname"] != args[4]]
            self.qdiscs.pop(args[4], None)
        elif args[:3] == ["tc", "qdisc", "add"]:
            interface = args[4]
            if args[-1] == "clsact":
                self.qdiscs[interface].append({"kind": "clsact", "handle": "ffff:", "parent": "ffff:fff1"})
            elif "netem" in args:
                self.qdiscs[interface] = [{"kind": "netem", "handle": "1:", "root": True,
                                          "options": {"limit": int(args[args.index("limit") + 1]),
                                                      "delay": 10000}, "bytes": 120, "drops": 0}]
            else:
                raise AssertionError(args)
        elif args[:3] == ["tc", "qdisc", "del"]:
            assert args[-1] == "clsact"
            self.qdiscs[args[4]] = [q for q in self.qdiscs[args[4]] if q["kind"] != "clsact"]
        elif args[:3] == ["tc", "filter", "add"]:
            port_key = "src_port" if "src_port" in args else "dst_port"
            self.filters["ingress"].append({
                "protocol": "ip", "pref": int(args[args.index("pref") + 1]), "kind": "flower",
                "options": {"handle": "0x1", "keys": {
                    "eth_type": "ipv4", "ip_proto": "tcp", "src_ip": args[args.index("src_ip") + 1],
                    port_key: int(args[args.index(port_key) + 1])},
                    "actions": [{"kind": "mirred", "mirred_action": "redirect", "direction": "egress",
                                 "to_dev": args[-1], "index": 42, "stats": {"bytes": 12}}]}})
        elif args[:3] == ["tc", "filter", "del"]:
            pref = int(args[args.index("pref") + 1])
            self.filters["ingress"] = [r for r in self.filters["ingress"] if r["pref"] != pref]
        else:
            raise AssertionError(args)
        return ""


class NetemTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.kernel = Kernel()
        self.controller = netem.Controller(Path(self.directory.name) / "state", self.kernel.run)

    def clear(self):
        return self.controller.dispatch({"action": "clear", "nonce": NONCE})

    def test_complete_lifecycle_preserves_physical_root_and_archives_counters(self):
        baseline = copy.deepcopy(self.kernel.qdiscs["eth0"])
        result = self.controller.dispatch(request())
        self.assertTrue(result["active_objects_complete"])
        self.assertTrue(result["physical_qdisc_configuration_unchanged"])
        self.assertEqual(len(result["owned_filters"]), 2)
        self.assertEqual(result["queue_limit_packets"], netem.QUEUE_LIMIT_PACKETS)
        cleared = self.clear()
        self.assertEqual(cleared["phase"], "cleared")
        self.assertEqual(self.kernel.qdiscs["eth0"], baseline)
        self.assertEqual(self.kernel.filters["ingress"], [])
        self.assertEqual(len(self.kernel.links), 1)
        self.assertEqual(cleared["cleanup"]["final_ifb_qdiscs"][0]["bytes"], 120)
        self.assertTrue(Path(cleared["state_path"]).exists())
        self.assertFalse(any("root" in args and "eth0" in args for args in self.kernel.mutations))

    def test_initiated_and_accepted_connections_select_data_and_reverse_ack(self):
        result = self.controller.dispatch(request(peers=[{"ip": "10.1.2.3", "port": 9000},
                                                        {"ip": "10.1.2.3", "port": 9002},
                                                        {"ip": "10.1.2.4", "port": 9000}],
                                                  local_ports=[9001, 9003]))
        keys = [row["options"]["keys"] for row in result["owned_filters"]]
        self.assertEqual(len(keys), 7)  # source endpoints + unique IP/local-port pairs
        self.assertTrue(all(k["ip_proto"] == "tcp" and k["src_ip"].startswith("10.1.2.") for k in keys))
        def matches(source_ip, source_port, destination_port):
            return sum(k["src_ip"] == source_ip and
                       (k.get("src_port") == source_port or k.get("dst_port") == destination_port)
                       for k in keys)
        self.assertEqual(matches("10.1.2.3", 50000, 9001), 1)
        self.assertEqual(matches("10.1.2.3", 9000, 50001), 1)
        self.assertEqual(matches("10.1.2.3", 22, 50001), 0)
        self.assertEqual(matches("10.1.2.8", 9000, 9001), 0)
        # Overlap may match two selectors, but mirred redirect consumes the packet.
        self.assertEqual(matches("10.1.2.3", 9000, 9001), 2)

    def test_existing_hook_and_unrelated_filters_are_retained(self):
        self.kernel.qdiscs["eth0"].append({"kind": "clsact", "handle": "ffff:"})
        foreign = {"pref": 10000, "kind": "bpf", "protocol": "all", "options": {"handle": "0x7"}}
        self.kernel.filters["ingress"].append(foreign)
        self.controller.dispatch(request())
        self.assertEqual(self.kernel.filters["ingress"][1]["pref"], 10001)
        self.clear()
        self.assertEqual(self.kernel.filters["ingress"], [foreign])
        self.assertTrue(any(q["kind"] == "clsact" for q in self.kernel.qdiscs["eth0"]))
        self.assertFalse(any(args[:3] == ["tc", "qdisc", "del"] for args in self.kernel.mutations))

    def test_new_foreign_egress_filter_prevents_shared_hook_deletion(self):
        self.controller.dispatch(request())
        foreign = {"pref": 44, "kind": "bpf", "protocol": "all", "options": {"handle": 8}}
        self.kernel.filters["egress"].append(foreign)
        result = self.clear()
        self.assertIn("unrelated filters", result["cleanup"]["retained_hook_reason"])
        self.assertEqual(self.kernel.filters["egress"], [foreign])
        self.assertTrue(any(q["kind"] == "clsact" for q in self.kernel.qdiscs["eth0"]))

    def test_configuration_is_idempotent_but_nonce_cannot_be_repurposed(self):
        self.controller.dispatch(request())
        count = len(self.kernel.mutations)
        self.controller.dispatch(request())
        self.assertEqual(len(self.kernel.mutations), count)
        with self.assertRaisesRegex(netem.NetemError, "different configuration"):
            self.controller.dispatch(request(delay_ms=20))
        self.assertEqual(len(self.kernel.mutations), count)
        self.clear()
        count = len(self.kernel.mutations)
        self.clear()
        self.assertEqual(len(self.kernel.mutations), count)
        with self.assertRaisesRegex(netem.NetemError, "fresh nonce"):
            self.controller.dispatch(request())

    def test_unknown_nonce_has_no_network_commands(self):
        self.assertEqual(self.clear()["phase"], "absent")
        self.assertEqual(self.kernel.commands, [])

    def test_partial_filter_failure_cleans_only_created_objects(self):
        self.kernel.fail = lambda args: args[:3] == ["tc", "filter", "add"] and "dst_port" in args
        with self.assertRaisesRegex(netem.NetemError, "owned state was cleared"):
            self.controller.dispatch(request())
        self.assertEqual(self.kernel.filters["ingress"], [])
        self.assertEqual([link["ifname"] for link in self.kernel.links], ["eth0"])
        self.assertEqual([q["kind"] for q in self.kernel.qdiscs["eth0"]], ["fq_codel"])
        state = json.loads((self.controller.root / NONCE / "state.json").read_text())
        self.assertEqual(state["phase"], "cleared")
        self.assertIn("injected", state["setup_error"])

    def test_changed_filter_refuses_cleanup_before_any_deletion(self):
        self.controller.dispatch(request())
        self.kernel.filters["ingress"][1]["options"]["keys"]["src_ip"] = "10.9.9.9"
        count = len(self.kernel.mutations)
        with self.assertRaisesRegex(netem.NetemError, "filter identity changed"):
            self.clear()
        self.assertEqual(len(self.kernel.mutations), count)

    def test_changed_ifb_alias_refuses_cleanup(self):
        self.controller.dispatch(request())
        self.kernel.links[1]["ifalias"] = "someone-else"
        count = len(self.kernel.mutations)
        with self.assertRaisesRegex(netem.NetemError, "IFB identity changed"):
            self.clear()
        self.assertEqual(len(self.kernel.mutations), count)

    def test_recreated_physical_interface_refuses_cleanup(self):
        self.controller.dispatch(request())
        self.kernel.links[0]["ifindex"] = 98
        count = len(self.kernel.mutations)
        with self.assertRaisesRegex(netem.NetemError, "physical interface identity changed"):
            self.clear()
        self.assertEqual(len(self.kernel.mutations), count)

    def test_foreign_ifb_qdisc_is_not_deleted(self):
        result = self.controller.dispatch(request())
        name = result["ifb"]["ifname"]
        self.kernel.qdiscs[name] = [{"kind": "htb", "handle": "9:", "root": True}]
        with self.assertRaisesRegex(netem.NetemError, "IFB qdisc changed"):
            self.clear()
        self.assertTrue(any(link["ifname"] == name for link in self.kernel.links))
        self.assertEqual(self.kernel.qdiscs[name][0]["kind"], "htb")

    def test_existing_ifb_name_is_never_reused(self):
        self.kernel.links.append({"ifindex": 50, "ifname": "dl" + NONCE[:12]})
        with self.assertRaisesRegex(netem.NetemError, "already exists"):
            self.controller.dispatch(request())
        self.assertEqual(self.kernel.mutations, [])

    def test_netem_missing_is_visible_in_status(self):
        result = self.controller.dispatch(request())
        self.kernel.qdiscs[result["ifb"]["ifname"]] = []
        status = self.controller.dispatch({"action": "status", "nonce": NONCE})
        self.assertFalse(status["active_objects_complete"])

    def test_invalid_input_is_rejected_before_network_or_state_changes(self):
        bad = [{"nonce": "../etc"}, {"interface": "eth0;bad"}, {"interface": "lo"},
               {"delay_ms": float("nan")}, {"delay_ms": -1}, {"loss_percent": 101},
               {"peers": [{"ip": "0.0.0.0/0", "port": 9000}]},
               {"peers": [{"ip": "127.0.0.1", "port": 9000}]},
               {"peers": [{"ip": "10.1.1.1", "port": 22}]},
               {"local_ports": [True]}, {"local_ports": []}, {"shell": "false"}]
        for changes in bad:
            with self.subTest(changes=changes), self.assertRaises(netem.NetemError):
                self.controller.dispatch(request(**changes))
        self.assertEqual(self.kernel.commands, [])
        self.assertFalse(self.controller.root.exists())

    def test_state_directory_must_be_private_and_not_symlinked(self):
        self.controller.root.mkdir(mode=0o755)
        with self.assertRaisesRegex(netem.NetemError, "private directory"):
            self.controller.dispatch(request())
        self.assertEqual(self.kernel.commands, [])


if __name__ == "__main__":
    unittest.main()
