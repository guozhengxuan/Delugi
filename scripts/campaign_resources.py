"""Immutable campaign inventories and verified whole-worker resource contracts."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

MAX_INVENTORY_BYTES = 32 * 1024**2
VERIFIED = "remote_effective_whole_worker_budget_verified"
UNVERIFIED_SWAP = "remote_swap_unverified_diagnostic"
CONTRACT_SCHEMA = 2


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def file_bytes(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_INVENTORY_BYTES + 1)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise ValueError("campaign inventory exceeds its metadata envelope")
    return raw


def digest(raw): return hashlib.sha256(raw).hexdigest()


def key(protocol, nodes): return f"{protocol}:n{nodes}"


def valid_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def validate_budget(budget):
    if (not isinstance(budget, dict) or budget.get("enforcement") not in ("dedicated_host", "cgroup")
            or not isinstance(budget.get("cpus"), list) or not budget["cpus"]
            or any(type(cpu) is not int or cpu < 0 for cpu in budget["cpus"])
            or len(set(budget["cpus"])) != len(budget["cpus"])
            or type(budget.get("memory_bytes")) is not int or budget["memory_bytes"] <= 0
            or ("swap_bytes" in budget and (type(budget["swap_bytes"]) is not int or budget["swap_bytes"] < 0))):
        raise ValueError("explicit enforced whole-validator CPU and memory budgets required")
    if budget["enforcement"] == "cgroup" and not budget.get("cgroup_parent"):
        raise ValueError("resource contract requires the delegated cgroup placement")


def snapshot_inventories(config, directory):
    directory = Path(directory); result = {}
    for protocol, sizes in sorted(config.get("remote_inventories", {}).items()):
        if protocol not in config["protocols"]: continue
        for n, source in sorted(sizes.items()):
            if int(n) not in config["nodes"]: continue
            path = Path(source).resolve(); raw = file_bytes(path); data = json.loads(raw)
            hosts = data["inventory"]["hosts"] if "receipts" in data else data["hosts"]
            trusted_hosts = {str(Path(host["known_hosts_file"]).expanduser().resolve()):
                             digest(file_bytes(Path(host["known_hosts_file"]).expanduser())) for host in hosts}
            destination = directory / f"{protocol}-n{int(n)}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as target: target.write(raw)
            result[key(protocol, int(n))] = {"source": str(path), "sha256": digest(raw),
                "snapshot": str(destination.resolve()), "known_hosts_sha256": trusted_hosts}
    return result


def read_inventory(source, protocol, nodes, snapshots=None):
    path = Path(source).resolve()
    if snapshots is None:
        raw = file_bytes(path)
        return json.loads(raw), digest(raw)
    record = snapshots[key(protocol, nodes)]
    if str(path) != record["source"] or digest(file_bytes(path)) != record["sha256"]:
        raise ValueError("campaign inventory/publication source changed after initial snapshot")
    for name, expected in record["known_hosts_sha256"].items():
        if digest(file_bytes(name)) != expected:
            raise ValueError("campaign SSH host-key inventory changed after initial snapshot")
    raw = file_bytes(record["snapshot"])
    if digest(raw) != record["sha256"]:
        raise ValueError("campaign inventory snapshot changed")
    return json.loads(raw), record["sha256"]


def static_placement(inventory):
    hosts = []
    for host in sorted(inventory["hosts"], key=lambda row: row["replica"]):
        budget = host["budget"]
        validate_budget(budget)
        # Record every declared resource setting, including optional disk/network
        # envelopes. Intentional per-trial netem presets live outside this object.
        hosts.append({"replica": host["replica"], "ssh": host["ssh"], "advertised": host["advertised"],
            "bind": host.get("bind"), "control_port": host["control_port"],
            "network_interface": host.get("network_interface"), "python_executable": host.get("python_executable", "python3"),
            "identity_file": str(Path(host["identity_file"]).expanduser().resolve()),
            "known_hosts_file": str(Path(host["known_hosts_file"]).expanduser().resolve()),
            "known_hosts_sha256": digest(file_bytes(Path(host["known_hosts_file"]).expanduser())),
            "budget": budget})
    return hosts


def effective_summary(summary, budget, nonce):
    if (summary.get("nonce") != nonce or summary.get("budget") != budget
            or summary.get("exit_code") != 0 or summary.get("native_exit_code") != 0
            or summary.get("timed_out") is not False or summary.get("owned_group_cleanup", {}).get("group_empty") is not True):
        raise ValueError("whole-worker execution/resource/cleanup evidence is incomplete")
    return validate_effective_budget(summary.get("effective_budget", {}), budget)


def validate_effective_budget(effective, budget):
    validate_budget(budget)
    mode = "physical_host" if budget["enforcement"] == "dedicated_host" else "cgroup_memory_max"
    memory = effective.get("memory_limit_bytes")
    if (effective.get("cpus") != budget["cpus"] or effective.get("memory_enforcement") != mode
            or type(memory) is not int or not 0 < memory <= budget["memory_bytes"]):
        raise ValueError("effective whole-worker CPU/memory budget differs from inventory")
    expected_cpu = "inherited_process_affinity" if mode == "physical_host" else "cgroup_quota_and_inherited_process_affinity"
    if effective.get("cpu_enforcement") != expected_cpu:
        raise ValueError("effective worker CPU enforcement is missing")
    if mode == "cgroup_memory_max" and memory != budget["memory_bytes"]:
        raise ValueError("effective cgroup memory limit differs from declared cap")
    if effective.get("swap_policy_verified") is True:
        declared, actual = budget.get("swap_bytes"), effective.get("swap_limit_bytes")
        if type(declared) is not int or declared < 0 or type(actual) is not int or not 0 <= actual <= declared:
            raise ValueError("effective swap allowance differs from declared budget")
        if mode == "physical_host":
            if (effective.get("swap_enforcement") != "observed_host_swap" or
                    type(effective.get("host_swap_bytes")) is not int or type(effective.get("host_swap_bytes_at_end")) is not int
                    or effective["host_swap_bytes"] != actual or effective["host_swap_bytes_at_end"] != actual):
                raise ValueError("dedicated-host swap observation is missing or changed")
        elif effective.get("swap_enforcement") != "cgroup_memory_swap_max" or actual != declared:
            raise ValueError("effective cgroup swap limit differs from declared cap")
    elif budget.get("swap_bytes") is not None:
        raise ValueError("declared swap policy lacks effective enforcement evidence")
    return effective


def budget_equivalence(budget, observed):
    return {"cpu_count": len(budget["cpus"]), "memory_bytes": budget["memory_bytes"],
        "enforcement": budget["enforcement"], "effective_cpu_count": len(observed["cpus"]),
        "effective_memory_bytes": observed["memory_limit_bytes"],
        "swap_bytes": budget.get("swap_bytes"), "effective_swap_bytes": observed.get("swap_limit_bytes"),
        "swap_enforcement": observed.get("swap_enforcement", "unavailable"),
        "additional_declared_budgets": {k: v for k, v in budget.items() if k not in
            ("cpus", "memory_bytes", "enforcement", "cgroup_parent")}}


def validate_verified_contract(contract, protocol=None, nodes=None):
    """Offline structural proof check; an old success label is not current proof.

    No filesystem or host lookup is performed during replay. The archived source
    hash and placement bind those inputs; requested/effective budgets and swap
    policy must be internally complete before formal acceptance or selection.
    """
    try:
        if (not isinstance(contract, dict) or type(contract.get("schema")) is not int
                or contract["schema"] != CONTRACT_SCHEMA or contract.get("validation") != VERIFIED):
            raise ValueError("current versioned resource contract with enforced whole-worker swap evidence required; legacy contracts are diagnostic only")
        count = contract["nodes"]
        if (type(count) is not int or count <= 0 or not isinstance(contract["protocol"], str)
                or not contract["protocol"] or (nodes is not None and count != nodes)
                or (protocol is not None and contract["protocol"] != protocol)):
            raise ValueError("resource contract protocol or committee differs")
        placement, effective = contract["placement"], contract["effective_budgets"]
        if (not isinstance(placement, list) or len(placement) != count or not isinstance(effective, dict)
                or set(effective) != {str(i) for i in range(count)}
                or any(type(host.get("replica")) is not int for host in placement)
                or sorted(host["replica"] for host in placement) != list(range(count))):
            raise ValueError("resource contract placement/effective population differs")
        if not valid_sha256(contract["inventory_source_sha256"]):
            raise ValueError("resource contract lacks immutable inventory/publication identity")
        equivalence = []
        for host in placement:
            if (any(not isinstance(host.get(name), str) or not host[name] for name in
                    ("ssh", "advertised", "identity_file", "known_hosts_file", "python_executable"))
                    or not valid_sha256(host.get("known_hosts_sha256"))
                    or type(host.get("control_port")) is not int or not 1 <= host["control_port"] <= 65535):
                raise ValueError("resource contract lacks exact static host placement")
            observed = validate_effective_budget(effective[str(host["replica"])], host["budget"])
            if observed.get("swap_policy_verified") is not True:
                raise ValueError("resource contract lacks verified swap evidence")
            equivalence.append(budget_equivalence(host["budget"], observed))
        equivalence.sort(key=lambda row: json.dumps(row, sort_keys=True))
        if contract["matched_budget_equivalence"] != equivalence:
            raise ValueError("resource contract counterpart budget summary differs from actual per-host proof")
        return contract
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed versioned resource contract: " + str(error)) from error


def verified_contract(case, config, data, inventory):
    if inventory is None:
        if config["purpose"] == "formal":
            raise ValueError("formal campaign requires verified matched whole-worker resource enforcement; local machine metadata is not an enforced budget")
        return {"validation": "local_unenforced_diagnostic", "protocol": case["protocol"], "nodes": case["nodes"]}
    trial = data.get("trial", data)
    deployment = trial["deployment"]
    expected = static_placement(inventory)
    if static_placement(deployment["inventory"]) != expected:
        raise ValueError("measured worker placement differs from selected inventory")
    machines = {str(i): row for i, row in deployment["machines"].items()}
    if set(machines) != {str(i) for i in range(case["nodes"])}:
        raise ValueError("whole-worker resource population differs from committee")
    effective = {}
    equivalence = []
    for host in expected:
        observed = effective_summary(machines[str(host["replica"])]["resource_summary"], host["budget"], deployment["nonce"])
        effective[str(host["replica"])] = observed
        budget = host["budget"]
        equivalence.append(budget_equivalence(budget, observed))
    source_hash = inventory.get("inventory_source_sha256", inventory.get("publication_sha256"))
    if not valid_sha256(source_hash):
        raise ValueError("initial inventory/publication hash missing from resource contract")
    swap_verified = all(row.get("swap_policy_verified") is True for row in effective.values())
    if config["purpose"] == "formal" and not swap_verified:
        raise ValueError("formal resource budget requires an explicit observed or enforced swap policy")
    equivalence.sort(key=lambda row: json.dumps(row, sort_keys=True))
    contract = {"schema": CONTRACT_SCHEMA, "validation": VERIFIED if swap_verified else UNVERIFIED_SWAP, "protocol": case["protocol"], "nodes": case["nodes"],
            "inventory_source_sha256": source_hash, "placement": expected, "effective_budgets": effective,
            "matched_budget_equivalence": equivalence,
            "swap_scope": "declared host swap observed before/after or cgroup memory.swap.max enforced" if swap_verified else "swap unavailable or undeclared; diagnostic only",
            "disk_network_scope": "additional disk/network envelopes are documented when supplied; no undeclared enforcement inferred"}
    if swap_verified:
        validate_verified_contract(contract, case["protocol"], case["nodes"])
    return contract


def accept_contract(registry, contract):
    identity = key(contract["protocol"], contract["nodes"])
    hashed = canonical_hash(contract)
    if identity in registry and registry[identity]["sha256"] != hashed:
        raise ValueError("campaign placement or effective resource budget changed between trials")
    if contract["validation"] == VERIFIED:
        validate_verified_contract(contract)
        for other in registry.values():
            value = other["contract"]
            if value["nodes"] != contract["nodes"]: continue
            if value["validation"] == VERIFIED:
                validate_verified_contract(value)
            if value["validation"] != VERIFIED or value["matched_budget_equivalence"] != contract["matched_budget_equivalence"]:
                raise ValueError("counterpart protocols do not have matched per-validator and total resource envelopes")
    elif any(value["contract"]["nodes"] == contract["nodes"] and value["contract"]["validation"] == VERIFIED for value in registry.values()):
        raise ValueError("cannot mix enforced remote resources and unenforced local placement in one comparison")
    registry[identity] = {"sha256": hashed, "contract": contract}
    return hashed
