#!/usr/bin/env python3
"""Run-owned Linux ingress netem; JSON request on stdin, JSON reply on stdout.

Only peer IPv4 TCP traffic involving a declared benchmark port is redirected to
a dedicated IFB. The physical interface's root qdisc is never changed. Both
connection directions (including ACKs to ephemeral client ports) are selected.
Use an external echo probe on these same ports before, during, and after a run;
a configured delay is not evidence of the actual observed one-way delay.

Requires Linux, iproute2 with JSON/flower/IFB support, and root. The privileged
entry point accepts no arbitrary shell commands or paths. State is retained in
/run/delugi-netem/<32-hex-nonce>/state.json for cleanup and audit.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


STATE_ROOT = Path("/run/delugi-netem")
MAX_REQUEST_BYTES = 65536
QUEUE_LIMIT_PACKETS = 10000
MAX_RULES = 1024
NONCE = re.compile(r"[0-9a-f]{32}\Z")
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")


class NetemError(RuntimeError):
    pass


def validate_request(request):
    if not isinstance(request, dict):
        raise NetemError("request must be a JSON object")
    action = request.get("action")
    if action not in {"configure", "status", "clear"}:
        raise NetemError("action must be configure, status, or clear")
    nonce = request.get("nonce")
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise NetemError("nonce must contain exactly 32 lowercase hexadecimal digits")
    allowed = {"action", "nonce", "interface", "peers", "local_ports", "delay_ms", "loss_percent"}
    if set(request) - allowed:
        raise NetemError("unknown request field")
    if action != "configure":
        return {"action": action, "nonce": nonce}
    interface = request.get("interface")
    if not isinstance(interface, str) or not INTERFACE.fullmatch(interface) or interface == "lo":
        raise NetemError("interface must be a non-loopback Linux interface name")

    def port(value):
        if type(value) is not int or not 1024 <= value <= 65535:
            raise NetemError("benchmark ports must be integers between 1024 and 65535")
        return value

    raw_peers = request.get("peers")
    if not isinstance(raw_peers, list) or not 1 <= len(raw_peers) <= 128:
        raise NetemError("peers must contain 1 to 128 IPv4 TCP endpoints")
    peers = set()
    for peer in raw_peers:
        if not isinstance(peer, dict) or set(peer) != {"ip", "port"}:
            raise NetemError("each peer must contain only ip and port")
        if not isinstance(peer["ip"], str):
            raise NetemError("peer ip must be a literal IPv4 string")
        try:
            address = ipaddress.IPv4Address(peer["ip"])
        except (ValueError, TypeError) as error:
            raise NetemError("peer ip must be a literal IPv4 address") from error
        if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise NetemError("peer ip must be a unicast non-loopback IPv4 address")
        peers.add((str(address), port(peer["port"])))
    raw_ports = request.get("local_ports")
    if not isinstance(raw_ports, list) or not 1 <= len(raw_ports) <= 32:
        raise NetemError("local_ports must contain 1 to 32 benchmark TCP ports")
    ports = sorted({port(value) for value in raw_ports})
    if len(peers) + len({ip for ip, _ in peers}) * len(ports) > MAX_RULES:
        raise NetemError("scoped filter count exceeds the 1024-rule bound")

    def bounded_number(name, maximum, default=None):
        value = request.get(name, default)
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
            raise NetemError(f"{name} must be finite and between 0 and {maximum}")
        return float(value)

    return {"action": action, "nonce": nonce, "interface": interface,
            "peers": [{"ip": ip, "port": value} for ip, value in sorted(peers)],
            "local_ports": ports, "delay_ms": bounded_number("delay_ms", 1000),
            "loss_percent": bounded_number("loss_percent", 100, 0)}


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        raise NetemError(f"{' '.join(argv)} failed: {result.stderr.strip()[:2000]}")
    return result.stdout


def _handle(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0) if value.startswith("0x") else int(value, 16)
        except ValueError:
            return None
    return None


def _static_qdiscs(qdiscs):
    """Compare configuration, excluding counters that necessarily change."""
    return [{key: value for key, value in qdisc.items()
             if key in {"kind", "handle", "parent", "root", "options"}}
            for qdisc in qdiscs if qdisc.get("kind") not in {"ingress", "clsact"}]


class Controller:
    def __init__(self, state_root=STATE_ROOT, run=command):
        self.root = Path(state_root)
        self.run = run

    def _json(self, args):
        value = json.loads(self.run(args))
        if not isinstance(value, list):
            raise NetemError("iproute2 did not return a JSON list")
        return value

    def _links(self):
        return self._json(["ip", "-j", "-d", "link", "show"])

    def _qdiscs(self, interface):
        return self._json(["tc", "-s", "-j", "qdisc", "show", "dev", interface])

    def _filters(self, interface, hook="ingress"):
        return self._json(["tc", "-s", "-j", "filter", "show", "dev", interface, hook])

    @contextlib.contextmanager
    def _lock(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise NetemError("state root must be an owned private directory")
        descriptor = os.open(self.root / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _save(self, state):
        directory = self.root / state["nonce"]
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise NetemError("run state must be an owned private directory")
        # The parent is private to root; replace is atomic across interrupted calls.
        temporary = directory / "state.tmp"
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(state, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(directory / "state.json")

    def _load(self, nonce):
        path = self.root / nonce / "state.json"
        if not path.exists():
            return None
        if path.is_symlink() or path.parent.is_symlink():
            raise NetemError("refusing symlinked state")
        with path.open() as source:
            state = json.load(source)
        if state.get("nonce") != nonce or state.get("schema") != "delugi-linux-netem-v1":
            raise NetemError("run state identity mismatch")
        return state

    def dispatch(self, request):
        request = validate_request(request)
        with self._lock():
            if request["action"] == "configure":
                return self._configure(request)
            state = self._load(request["nonce"])
            if state is None:
                return {"nonce": request["nonce"], "phase": "absent", "mutated": False}
            if request["action"] == "clear":
                return self._clear(state)
            return self._status(state)

    def _configure(self, request):
        config = {key: value for key, value in request.items() if key != "action"}
        previous = self._load(request["nonce"])
        if previous:
            if previous["config"] != config:
                raise NetemError("nonce already belongs to a different configuration")
            if previous["phase"] != "active":
                raise NetemError("nonce has an incomplete or cleared run; clear it and use a fresh nonce")
            return self._status(previous)
        interface = config["interface"]
        links = self._links()
        physical = next((link for link in links if link["ifname"] == interface), None)
        if physical is None or physical.get("linkinfo", {}).get("info_kind") == "ifb":
            raise NetemError("interface must exist and must not itself be an IFB")
        ifb = "dl" + request["nonce"][:12]
        if any(link["ifname"] == ifb for link in links):
            raise NetemError("run IFB name already exists; refusing to reuse it")
        qdiscs = self._qdiscs(interface)
        hooks = [q for q in qdiscs if q.get("kind") in {"clsact", "ingress"}]
        if len(hooks) > 1:
            raise NetemError("ambiguous ingress hook")
        if not hooks and any(q.get("handle") == "ffff:" for q in qdiscs):
            raise NetemError("reserved ingress handle is already occupied")
        existing = self._filters(interface) if hooks else []
        used = {int(item["pref"]) for item in existing if "pref" in item}
        matches = [(peer["ip"], "src_port", peer["port"]) for peer in config["peers"]]
        matches += [(ip, "dst_port", port) for ip in sorted({p["ip"] for p in config["peers"]})
                    for port in config["local_ports"]]
        priorities = [value for value in range(10000, 65000) if value not in used][:len(matches)]
        if len(priorities) != len(matches):
            raise NetemError("no free scoped filter priorities")
        rules = [{"pref": pref, "handle": 1, "ip": ip, "port_key": key, "port": port}
                 for pref, (ip, key, port) in zip(priorities, matches)]
        state = {"schema": "delugi-linux-netem-v1", "nonce": config["nonce"], "config": config,
                 "phase": "preparing", "created_unix": time.time(), "ifb": ifb,
                 "ifb_alias": "delugi-netem:" + config["nonce"], "ifb_ifindex": None,
                 "interface_ifindex": physical["ifindex"], "created_hook": not bool(hooks),
                 "hook_add_attempted": False, "hook_add_confirmed": False, "ifb_add_attempted": False,
                 "rules": rules, "attempted_rules": [], "baseline_qdiscs": qdiscs,
                 "baseline_ingress_filters": existing,
                 "queue_limit_packets": QUEUE_LIMIT_PACKETS,
                 "scope": "ingress IPv4 TCP from peer IP with source peer port or destination local port; ACKs included",
                 "delay_placement": "once on receipt at each configured replica, including TCP ACKs",
                 "calibration": "external same-port echo RTT before/during/after required"}
        self._save(state)
        try:
            state["ifb_add_attempted"] = True
            self._save(state)
            self.run(["ip", "link", "add", "name", ifb, "type", "ifb"])
            created = next(link for link in self._links() if link["ifname"] == ifb)
            state["ifb_ifindex"] = created["ifindex"]
            self._save(state)
            self.run(["ip", "link", "set", "dev", ifb, "alias", state["ifb_alias"]])
            self.run(["ip", "link", "set", "dev", ifb, "up"])
            self.run(["tc", "qdisc", "add", "dev", ifb, "root", "handle", "1:", "netem",
                      "limit", str(QUEUE_LIMIT_PACKETS), "delay", f"{config['delay_ms']:g}ms",
                      "loss", "random", f"{config['loss_percent']:g}%"])
            state["ifb_qdisc_configuration"] = _static_qdiscs(self._qdiscs(ifb))
            self._save(state)
            if state["created_hook"]:
                state["hook_add_attempted"] = True
                self._save(state)
                self.run(["tc", "qdisc", "add", "dev", interface, "handle", "ffff:", "clsact"])
                state["hook_add_confirmed"] = True
                self._save(state)
            for rule in rules:
                state["attempted_rules"].append(rule)
                self._save(state)
                self.run(["tc", "filter", "add", "dev", interface, "ingress", "protocol", "ip",
                          "pref", str(rule["pref"]), "chain", "0", "handle", "0x1", "flower", "skip_hw",
                          "src_ip", rule["ip"], "ip_proto", "tcp", rule["port_key"], str(rule["port"]),
                          "action", "mirred", "egress", "redirect", "dev", ifb])
            state["phase"] = "active"
            self._save(state)
            result = self._status(state)
            if not result["active_objects_complete"]:
                raise NetemError("installed IFB, netem, or filter inventory is incomplete")
            return result
        except Exception as error:
            state["setup_error"] = str(error)
            state["phase"] = "setup_failed"
            self._save(state)
            try:
                self._clear(state)
            except Exception as cleanup:
                raise NetemError(f"setup failed: {error}; cleanup incomplete: {cleanup}") from error
            raise NetemError(f"setup failed and owned state was cleared: {error}") from error

    def _owned_link(self, state, links):
        link = next((link for link in links if link["ifname"] == state["ifb"]), None)
        if link is None:
            return None
        if (link.get("linkinfo", {}).get("info_kind") != "ifb"
                or link.get("ifindex") != state["ifb_ifindex"]
                or link.get("ifalias") != state["ifb_alias"]):
            raise NetemError("IFB identity changed or creation was interrupted before ownership was recorded")
        return link

    @staticmethod
    def _matches_rule(item, rule, ifb):
        options = item.get("options", {})
        keys = options.get("keys", {})
        actions = options.get("actions", [])
        source = str(keys.get("src_ip", ""))
        if source.endswith("/32"):
            source = source[:-3]
        return (item.get("kind") == "flower" and item.get("protocol") == "ip"
                and int(item.get("chain", 0)) == 0
                and int(item.get("pref", -1)) == rule["pref"]
                and _handle(options.get("handle", item.get("handle"))) == rule["handle"]
                and source == rule["ip"] and keys.get("ip_proto") in {"tcp", 6}
                and set(keys) <= {"eth_type", "src_ip", "ip_proto", rule["port_key"]}
                and str(keys.get(rule["port_key"])) == str(rule["port"])
                and len(actions) == 1 and actions[0].get("kind") == "mirred"
                and actions[0].get("to_dev") == ifb
                and actions[0].get("mirred_action") == "redirect"
                and actions[0].get("direction") == "egress")

    def _verify_physical(self, state, links):
        physical = next((link for link in links if link["ifname"] == state["config"]["interface"]), None)
        if physical is None or physical.get("ifindex") != state["interface_ifindex"]:
            raise NetemError("physical interface identity changed; refusing filter mutation")

    def _status(self, state):
        links = self._links()
        self._verify_physical(state, links)
        owned = self._owned_link(state, links)
        interface = state["config"]["interface"]
        qdiscs = self._qdiscs(interface)
        filters = self._filters(interface) if any(q.get("kind") in {"ingress", "clsact"} for q in qdiscs) else []
        live = [item for item in filters if any(self._matches_rule(item, rule, state["ifb"])
                                                for rule in state["attempted_rules"])]
        ifb_qdiscs = self._qdiscs(state["ifb"]) if owned else []
        healthy = (owned is not None and len(live) == len(state["rules"])
                   and any(q.get("kind") == "netem" and q.get("handle") == "1:" and q.get("root")
                           for q in ifb_qdiscs)
                   and _static_qdiscs(ifb_qdiscs) == state.get("ifb_qdisc_configuration"))
        return {"nonce": state["nonce"], "phase": state["phase"], "config": state["config"],
                "active_objects_complete": healthy, "ifb": owned, "owned_filters": live,
                "ifb_qdiscs": ifb_qdiscs,
                "interface_qdiscs": qdiscs,
                "physical_qdisc_configuration_unchanged": _static_qdiscs(qdiscs) == _static_qdiscs(state["baseline_qdiscs"]),
                "queue_limit_packets": state["queue_limit_packets"], "scope": state["scope"],
                "delay_placement": state["delay_placement"], "calibration": state["calibration"],
                "state_path": str(self.root / state["nonce"] / "state.json"),
                "cleanup": state.get("cleanup")}

    def _clear(self, state):
        if state["phase"] == "cleared":
            return self._status(state)
        links = self._links()
        self._verify_physical(state, links)
        owned = self._owned_link(state, links)
        final_ifb = self._qdiscs(state["ifb"]) if owned else []
        if owned and (any(q.get("kind") != "noqueue" and not
                          (q.get("kind") == "netem" and q.get("handle") == "1:" and q.get("root"))
                          for q in final_ifb)
                      or ("ifb_qdisc_configuration" in state and
                          _static_qdiscs(final_ifb) != state["ifb_qdisc_configuration"])):
            raise NetemError("run IFB qdisc changed; refusing to delete unrelated configuration")
        interface = state["config"]["interface"]
        qdiscs = self._qdiscs(interface)
        hook = next((q for q in qdiscs if q.get("kind") in {"ingress", "clsact"}), None)
        filters = self._filters(interface) if hook else []
        # Validate every deletion target first, including IFB identity above.
        delete = []
        for rule in state["attempted_rules"]:
            candidates = [item for item in filters if int(item.get("pref", -1)) == rule["pref"]
                          and int(item.get("chain", 0)) == 0
                          and _handle(item.get("options", {}).get("handle", item.get("handle"))) == rule["handle"]]
            if any(not self._matches_rule(item, rule, state["ifb"]) for item in candidates):
                raise NetemError("owned filter identity changed; refusing to delete it")
            delete.extend(rule for _ in candidates)
        state["phase"] = "clearing"
        self._save(state)
        for rule in delete:
            self.run(["tc", "filter", "del", "dev", interface, "ingress", "protocol", "ip",
                      "pref", str(rule["pref"]), "chain", "0", "handle", "0x1", "flower"])
        # Recheck after deletion. Never remove a hook containing someone else's filter.
        kept_hook = None
        if state["created_hook"] and state["hook_add_confirmed"] and hook:
            if hook.get("kind") != "clsact" or hook.get("handle") != "ffff:":
                kept_hook = "ingress hook changed; retained"
            elif self._filters(interface) or self._filters(interface, "egress"):
                kept_hook = "unrelated filters present; retained shared clsact hook"
            else:
                self.run(["tc", "qdisc", "del", "dev", interface, "clsact"])
        # An IFB is per-run; refuse to delete it if another filter now points to it.
        remaining = self._filters(interface) if kept_hook or (hook and not state["created_hook"]) else []
        if any(action.get("to_dev") == state["ifb"] for item in remaining
               for action in item.get("options", {}).get("actions", [])):
            raise NetemError("another filter references the run IFB; retain it for explicit review")
        if owned:
            # Persist final netem drop/backlog counters before deleting the device.
            state["final_ifb_qdiscs"] = final_ifb
            self._save(state)
            self.run(["ip", "link", "del", "dev", state["ifb"]])
        state["phase"] = "cleared"
        state["cleared_unix"] = time.time()
        state["cleanup"] = {"deleted_owned_filters": len(delete), "retained_hook_reason": kept_hook,
                            "final_ifb_qdiscs": state.get("final_ifb_qdiscs", [])}
        self._save(state)
        return self._status(state)


def main():
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise NetemError("this helper must run as root on Linux")
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise NetemError("request exceeds 64 KiB")
        result = Controller().dispatch(json.loads(raw))
        print(json.dumps({"ok": True, "result": result}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
