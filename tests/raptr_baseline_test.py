"""Reject misleading Raptr measurements without launching native replicas."""
import importlib.util
import json
from pathlib import Path
import signal
import statistics
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "raptr_baseline", ROOT / "scripts/baselines/raptr.py"
)
RAPTR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RAPTR)

INCLUSIONS = "quorum_store_num_txns_per_block_sum"
BLOCKS = "raikou_block_commit_rate"
COMPLETIONS = "raikou_mempool_insert_to_commit_latency_count"
COMPLETION_SECONDS = "raikou_mempool_insert_to_commit_latency_sum"
BATCH_COUNT = 'aptos_consensus_block_tracing_count{stage="BATCHCOMMIT"}'
BATCH_SECONDS = 'aptos_consensus_block_tracing_sum{stage="BATCHCOMMIT"}'
BLOCK_COUNT = 'aptos_consensus_block_tracing_count{stage="COMMITBLOCK"}'
BLOCK_SECONDS = 'aptos_consensus_block_tracing_sum{stage="COMMITBLOCK"}'


def snapshots():
    """Four observers of one workload, with uneven local ingress shares."""
    before, after = [], []
    for node, (inclusions, completed, elapsed) in enumerate(
        zip((98, 99, 101, 102), (5, 15, 25, 55), (0.05, 0.30, 0.75, 2.20))
    ):
        start = {
            INCLUSIONS: 1000,
            BLOCKS: 100,
            COMPLETIONS: 200,
            COMPLETION_SECONDS: 20,
            "raptr_baseline_transaction_bytes": 512,
            "raptr_baseline_ingress_transactions": 1000,
            "raptr_baseline_ingress_transaction_bytes": 512000,
            "raptr_baseline_tcp_written_bytes": 10000,
            "raptr_baseline_tcp_read_bytes": 9000,
            BATCH_COUNT: 30,
            BATCH_SECONDS: 3,
            BLOCK_COUNT: 40,
            BLOCK_SECONDS: 4,
            # Unrelated stages must not enter either reported latency.
            'aptos_consensus_block_tracing_count{stage="RECEIVED"}': 100,
            'aptos_consensus_block_tracing_sum{stage="RECEIVED"}': 100,
        }
        end = dict(start)
        end.update({
            INCLUSIONS: start[INCLUSIONS] + inclusions,
            "raptr_baseline_ingress_transactions": 1000 + completed + 1,
            "raptr_baseline_ingress_transaction_bytes": 512000 + (completed + 1) * 512,
            "raptr_baseline_tcp_written_bytes": 10000 + (node + 1) * 1000,
            "raptr_baseline_tcp_read_bytes": 9000 + (node + 1) * 999,
            BLOCKS: start[BLOCKS] + 10,
            COMPLETIONS: start[COMPLETIONS] + completed,
            COMPLETION_SECONDS: start[COMPLETION_SECONDS] + elapsed,
            BATCH_COUNT: start[BATCH_COUNT] + node + 1,
            BATCH_SECONDS: start[BATCH_SECONDS] + (0.01, 0.04, 0.09, 0.16)[node],
            BLOCK_COUNT: start[BLOCK_COUNT] + 2 * (node + 1),
            BLOCK_SECONDS: start[BLOCK_SECONDS] + (0.1, 0.4, 0.9, 1.6)[node],
            'aptos_consensus_block_tracing_count{stage="RECEIVED"}': 100000,
            'aptos_consensus_block_tracing_sum{stage="RECEIVED"}': 100000,
        })
        before.append(start)
        after.append(end)
    return before, after


def prometheus(snapshot):
    return "# Native counters after warmup\n" + "\n".join(
        f"{key} {value}" for key, value in snapshot.items()
    ) + "\n"


def summarize(before, after, seconds=10):
    return RAPTR.summarize(
        [prometheus(row) for row in before],
        [prometheus(row) for row in after],
        seconds,
    )


class RaptrMeasurementTests(unittest.TestCase):
    def test_ingress_completions_are_summed_but_replica_inclusions_are_not(self):
        before, after = snapshots()
        result = summarize(before, after)
        self.assertEqual(result["unique_ingress_completions"], 100)
        self.assertAlmostEqual(result["unique_ingress_completion_tps"], 10)
        self.assertEqual(
            [row["committed_transaction_inclusions"] for row in result["replicas"]],
            [98, 99, 101, 102],
        )
        # The network ordered about 100 transactions, not 400 transactions.
        rates = [row["committed_transaction_inclusions_per_second"]
                 for row in result["replicas"]]
        self.assertAlmostEqual(statistics.median(rates), 10)
        self.assertAlmostEqual(result["median_replica_inclusion_tps"], 10)
        self.assertNotEqual(result["unique_ingress_completion_tps"], sum(rates))

    def test_transaction_latency_is_weighted_by_completions_and_uses_ms(self):
        before, after = snapshots()
        result = summarize(before, after)
        self.assertAlmostEqual(result["ingress_to_materialized_commit_mean_ms"], 33)
        local_means = [row["local_ingress_completion_mean_ms"]
                       for row in result["replicas"]]
        for observed, expected in zip(local_means, (10, 20, 30, 40)):
            self.assertAlmostEqual(observed, expected)
        self.assertNotAlmostEqual(
            result["ingress_to_materialized_commit_mean_ms"],
            statistics.mean(local_means),
        )

    def test_tcp_writes_are_summed_once_and_not_added_to_reads(self):
        before, after = snapshots()
        result = summarize(before, after)
        self.assertEqual(result["replica_tcp_written_bytes"], 10000)
        self.assertEqual(result["replica_tcp_read_bytes"], 9990)
        self.assertEqual(result["replica_tcp_written_bytes_per_second"], 1000)
        self.assertEqual(result["replica_tcp_written_bytes_per_unique_completion"], 100)

    def test_actual_admission_and_backlog_are_separate_from_completion(self):
        before, after = snapshots()
        result = summarize(before, after)
        self.assertEqual(result["admitted_transactions"], 104)
        self.assertEqual(result["admitted_tx_s"], 10.4)
        self.assertEqual(result["pending_local_transactions_start"], 3200)
        self.assertEqual(result["pending_local_transactions_end"], 3204)

    def test_negative_pending_scrape_estimate_is_preserved_without_changing_measurements(self):
        before, after = snapshots()
        original = summarize(before, after)
        before[1]["raptr_baseline_ingress_transactions"] = before[1][COMPLETIONS]
        before[1]["raptr_baseline_ingress_transaction_bytes"] = before[1][COMPLETIONS] * 512
        after[1]["raptr_baseline_ingress_transactions"] = after[1][COMPLETIONS] - 1
        after[1]["raptr_baseline_ingress_transaction_bytes"] = after[1][COMPLETIONS] * 512
        result = summarize(before, after)
        node = result["replicas"][1]
        self.assertEqual(node["pending_local_transactions_start"], 0)
        self.assertEqual(node["pending_local_transactions_end"], -1)
        self.assertFalse(node["pending_snapshot_negative_start"])
        self.assertTrue(node["pending_snapshot_negative_end"])
        self.assertTrue(result["pending_snapshot_skew_detected"])
        self.assertEqual(node["pending_counter_snapshots"]["end"], {"admitted": 214, "completed": 215})
        self.assertEqual(node["admitted_byte_counter_skew"], 512)
        for key in ["unique_ingress_completions", "unique_ingress_completion_tps",
                    "ingress_to_materialized_commit_mean_ms", "replica_tcp_written_bytes",
                    "replica_tcp_read_bytes", "replica_tcp_written_bytes_per_second"]:
            self.assertEqual(result[key], original[key])
        args = SimpleNamespace(nodes=4, rate=1000, transaction_bytes=512, warmup=10, ingress_batch_ms=100, delta_ms=100)
        self.assertTrue(RAPTR.comparison(args, result)["pending_snapshot_skew_detected"])

    def test_negative_start_pending_estimate_is_also_preserved(self):
        before, after = snapshots()
        before[1]["raptr_baseline_ingress_transactions"] = before[1][COMPLETIONS] - 1
        result = summarize(before, after)
        self.assertEqual(result["replicas"][1]["pending_local_transactions_start"], -1)
        self.assertTrue(result["replicas"][1]["pending_snapshot_negative_start"])
        self.assertTrue(result["pending_snapshot_skew_detected"])

    def test_negative_cumulative_counters_cannot_hide_behind_positive_deltas(self):
        for metric in [INCLUSIONS, BLOCKS, COMPLETIONS, COMPLETION_SECONDS,
                       "raptr_baseline_ingress_transactions", "raptr_baseline_ingress_transaction_bytes",
                       "raptr_baseline_tcp_written_bytes", "raptr_baseline_tcp_read_bytes"]:
            with self.subTest(metric=metric):
                before, after = snapshots()
                before[1][metric], after[1][metric] = -2, -1
                with self.assertRaisesRegex(ValueError, "cumulative metric"):
                    summarize(before, after)

    def test_parser_failure_retains_exact_measurement_timing_and_scrape_spreads(self):
        before, after = snapshots()
        after[1][COMPLETIONS] = before[1][COMPLETIONS] - 1
        manifest = {"metrics": {}}
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            with self.assertRaises(ValueError):
                RAPTR.analyze_measurement(archive, manifest,
                    [prometheus(row) for row in before], [prometheus(row) for row in after],
                    100.125, 130.375, .0625, .125, 512)
            persisted = json.loads((archive / "measurement-window.json").read_text())
            self.assertEqual(persisted, manifest["measurement_window"])
            self.assertEqual(persisted["measurement_seconds"], 30.25)
            self.assertEqual(persisted["start_midpoint_monotonic_seconds"], 100.125)
            self.assertEqual(persisted["end_midpoint_monotonic_seconds"], 130.375)
            self.assertEqual(persisted["snapshot_spread_seconds"], {"start": .0625, "end": .125})
            self.assertEqual(manifest["metrics"], {})

    def test_missing_or_invalid_tcp_and_ingress_counters_cannot_pass(self):
        for metric in ["raptr_baseline_ingress_transactions", "raptr_baseline_ingress_transaction_bytes",
                       "raptr_baseline_tcp_written_bytes", "raptr_baseline_tcp_read_bytes"]:
            for issue in ["missing", "reset", "nonfinite"]:
                with self.subTest(metric=metric, issue=issue):
                    before, after = snapshots()
                    if issue == "missing":
                        del after[0][metric]
                    elif issue == "reset":
                        after[0][metric] = before[0][metric] - 1
                    else:
                        after[0][metric] = float("nan")
                    with self.assertRaises(ValueError):
                        summarize(before, after)

    def test_mismatched_runtime_serialized_size_assertion_is_rejected(self):
        before, after = snapshots()
        after[0]["raptr_baseline_transaction_bytes"] = 513
        with self.assertRaises(ValueError):
            summarize(before, after)

    def test_nonatomic_ingress_byte_counter_scrape_skew_is_reported(self):
        before, after = snapshots()
        after[0]["raptr_baseline_ingress_transaction_bytes"] += 512
        result = summarize(before, after)
        self.assertEqual(result["replicas"][0]["admitted_byte_counter_skew"], 512)

    def test_comparison_contract_preserves_native_endpoint_and_does_not_invent_generation(self):
        before, after = snapshots()
        metrics = summarize(before, after)
        args = SimpleNamespace(nodes=4, rate=1000, transaction_bytes=512, warmup=10, ingress_batch_ms=100, delta_ms=100)
        result = RAPTR.comparison(args, metrics)
        self.assertEqual(result["unique_completion_tps"], 10)
        self.assertEqual(result["replica_tcp_written_bytes"], 10000)
        self.assertEqual(result["admitted_count"], 104)
        self.assertIsNone(result["generated_count"])
        self.assertEqual(result["traffic_boundary"], "successful_replica_tcp_stream_writes")
        self.assertIn("ingress replica", result["latency_endpoint"])

    def test_native_stage_latencies_use_their_own_sample_weights(self):
        before, after = snapshots()
        result = summarize(before, after)
        self.assertEqual(result["latency"]["BATCHCOMMIT"]["samples"], 10)
        self.assertAlmostEqual(result["latency"]["BATCHCOMMIT"]["mean_ms"], 30)
        self.assertEqual(result["latency"]["COMMITBLOCK"]["samples"], 20)
        self.assertAlmostEqual(result["latency"]["COMMITBLOCK"]["mean_ms"], 150)

    def test_missing_start_counters_cannot_include_warmup_as_measured_work(self):
        for name in (INCLUSIONS, BLOCKS, COMPLETIONS, COMPLETION_SECONDS):
            with self.subTest(metric=name):
                before, after = snapshots()
                del before[1][name]
                with self.assertRaises(ValueError):
                    summarize(before, after)

    def test_missing_end_counters_cannot_be_silently_dropped(self):
        for name in (INCLUSIONS, BLOCKS, COMPLETIONS, COMPLETION_SECONDS):
            with self.subTest(metric=name):
                before, after = snapshots()
                del after[1][name]
                with self.assertRaises(ValueError):
                    summarize(before, after)

    def test_counter_resets_cannot_be_hidden_by_other_replicas_progress(self):
        for name in (INCLUSIONS, BLOCKS, COMPLETIONS, COMPLETION_SECONDS):
            with self.subTest(metric=name):
                before, after = snapshots()
                after[1][name] = before[1][name] - 1
                with self.assertRaises(ValueError):
                    summarize(before, after)

    def test_empty_blocks_do_not_count_as_useful_completion(self):
        before, after = snapshots()
        for first, last in zip(before, after):
            last[INCLUSIONS] = first[INCLUSIONS]
            last[COMPLETIONS] = first[COMPLETIONS]
            last[COMPLETION_SECONDS] = first[COMPLETION_SECONDS]
        with self.assertRaises(ValueError):
            summarize(before, after)

    def test_commit_inclusions_without_materialization_do_not_pass(self):
        before, after = snapshots()
        after[2][COMPLETIONS] = before[2][COMPLETIONS]
        after[2][COMPLETION_SECONDS] = before[2][COMPLETION_SECONDS]
        with self.assertRaises(ValueError):
            summarize(before, after)

    def test_every_replica_must_observe_consensus_progress(self):
        before, after = snapshots()
        after[2][INCLUSIONS] = before[2][INCLUSIONS]
        with self.assertRaises(ValueError):
            summarize(before, after)

    def test_nonfinite_telemetry_cannot_pass_progress_checks(self):
        for name in (INCLUSIONS, COMPLETIONS, COMPLETION_SECONDS):
            for invalid in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(metric=name, value=invalid):
                    before, after = snapshots()
                    after[1][name] = invalid
                    with self.assertRaises(ValueError):
                        summarize(before, after)

    def test_missing_replica_snapshots_cannot_shrink_the_committee(self):
        before, after = snapshots()
        for first, last in ((before, after[:3]), (before[:3], after), ([], [])):
            with self.subTest(before=len(first), after=len(last)):
                with self.assertRaises(ValueError):
                    summarize(first, last)

    def test_invalid_measurement_window_is_rejected(self):
        before, after = snapshots()
        for seconds in (0, -1, float("nan"), float("inf")):
            with self.subTest(seconds=seconds):
                with self.assertRaises(ValueError):
                    summarize(before, after, seconds)


class RaptrMatchedIngressTests(unittest.TestCase):
    def test_native_default_preserves_one_transaction_requests(self):
        shape = RAPTR.ingress_shape(1000, 4, 0)
        self.assertEqual(shape["transactions_per_request"], 1)
        self.assertEqual(shape["staggered_slots_per_origin"], 250)
        self.assertEqual(shape["request_interval_ms"], 4)

    def test_matched_cadence_preserves_exact_offered_load(self):
        for rate, expected in [(1000, 25), (4000, 100)]:
            with self.subTest(rate=rate):
                shape = RAPTR.ingress_shape(rate, 4, 100)
                self.assertEqual(shape["transactions_per_request"], expected)
                self.assertEqual(shape["staggered_slots_per_origin"], 10)
                self.assertEqual(shape["transactions_per_request"] * shape["staggered_slots_per_origin"] * 4, rate)

    def test_fractional_batches_slots_and_bad_rates_are_rejected(self):
        for rate, nodes, cadence in [(1004, 4, 100), (1000, 4, 333), (1000, 4, -1),
                                     (1000, 0, 100), (3, 4, 100), (1001, 4, 100)]:
            with self.subTest(rate=rate, nodes=nodes, cadence=cadence):
                with self.assertRaises(ValueError):
                    RAPTR.ingress_shape(rate, nodes, cadence)

    def test_all_origins_must_report_exact_native_request_framing(self):
        for rate, count in [(1000, 25), (4000, 100), (8000, 200)]:
            args = SimpleNamespace(rate=rate, nodes=4, ingress_batch_ms=100, transaction_bytes=512)
            prefix = 1 if count < 128 else 2
            lines = [f"RAPTR_BASELINE_WIRE client={i} txns={count} batch_bytes={count * 512 + prefix} transaction_bytes=512" for i in range(4)]
            samples = RAPTR.native_wire_samples("\n".join(lines), args)
            self.assertEqual(len(samples), 4)
            with self.assertRaises(RuntimeError):
                RAPTR.native_wire_samples("\n".join(lines[:3]), args)
            with self.assertRaises(RuntimeError):
                RAPTR.native_wire_samples("\n".join(lines).replace("transaction_bytes=512", "transaction_bytes=513", 1), args)
            with self.assertRaises(RuntimeError):
                RAPTR.native_wire_samples("\n".join(lines).replace(f"batch_bytes={count * 512 + prefix}", f"batch_bytes={count * 512}", 1), args)


class RaptrBuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.args = SimpleNamespace(source=root / "source", toolchain=root / "toolchain")
        (self.args.source / "target/release").mkdir(parents=True)
        self.forge = self.args.source / "target/release/forge"
        self.forge.write_bytes(b"small native Forge fixture\n")
        self.lock = self.args.source / "Cargo.lock"
        self.lock.write_text('version = 3\n# original locked dependencies\n')
        self.patch_file = root / "adapter.patch"
        self.patch_file.write_text("original local adapter patch\n")
        self.env = {
            "CONSENSUS_ONLY_PERF_TEST": "1",
            "CFLAGS": "-Dfdopen=fdopen",
            "CXXFLAGS": "-Dfdopen=fdopen",
            "RUSTFLAGS": "-C force-frame-pointers=yes",
        }
        self.native_state = {
            "commit": RAPTR.PIN,
            "diff": b"tracked native adapter changes\n",
            "compiler": "rustc 1.78.0\nhost: aarch64-apple-darwin\n",
        }
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(RAPTR, "PATCH", self.patch_file).start()
        mock.patch.object(
            RAPTR.subprocess, "check_output", side_effect=self.native_output
        ).start()

    def native_output(self, argv, **kwargs):
        # Exercise the real identity/stamp logic, without git, Rust, or builds.
        if argv[0] == "git" and argv[1] == "diff":
            return self.native_state["diff"]
        if argv[0] == "git" and argv[1] == "rev-parse":
            return self.native_state["commit"] + "\n"
        if Path(argv[0]).name == "rustc" and "--version" in argv:
            return self.native_state["compiler"]
        raise AssertionError(f"Unexpected external command: {argv}")

    def write_stamp(self):
        return RAPTR.write_build_stamp(self.args, self.env)

    def test_exact_build_stamp_accepts_the_recorded_binary_and_inputs(self):
        written = self.write_stamp()
        verified = RAPTR.verify_build_stamp(self.args, dict(self.env))
        self.assertEqual(verified, written)
        on_disk = json.loads(
            (self.args.source / "target/delugi-baseline-build.json").read_text()
        )
        self.assertEqual(on_disk, written)

    def test_missing_stamp_does_not_certify_a_preexisting_executable(self):
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_other_source_commit_is_rejected(self):
        self.write_stamp()
        self.native_state["commit"] = "b" * 40
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_changed_native_source_under_same_commit_is_rejected(self):
        self.write_stamp()
        self.native_state["diff"] = b"different implementation under the same pin\n"
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_changed_lockfile_is_rejected(self):
        self.write_stamp()
        self.lock.write_text('version = 3\n# different locked dependency\n')
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_changed_adapter_patch_is_rejected(self):
        self.write_stamp()
        self.patch_file.write_text("different local adapter patch\n")
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_changed_compiler_is_rejected(self):
        self.write_stamp()
        self.native_state["compiler"] = "rustc 1.79.0\nhost: aarch64-apple-darwin\n"
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)

    def test_changed_or_removed_compile_environment_is_rejected(self):
        self.write_stamp()
        for key in self.env:
            for remove in (False, True):
                with self.subTest(variable=key, removed=remove):
                    changed = dict(self.env)
                    if remove:
                        del changed[key]
                    else:
                        changed[key] += "-changed"
                    with self.assertRaises(RuntimeError):
                        RAPTR.verify_build_stamp(self.args, changed)

    def test_replaced_forge_executable_is_rejected(self):
        self.write_stamp()
        self.forge.write_bytes(b"a different small Forge binary fixture\n")
        with self.assertRaises(RuntimeError):
            RAPTR.verify_build_stamp(self.args, self.env)


class RaptrTimingAndShapingTests(unittest.TestCase):
    @staticmethod
    def config_text(base):
        return ("api:\n  address: 127.0.0.1:7000\n"
                "inspection_service:\n  port: 7001\n"
                "full_node_networks:\n  - listen_address: /ip4/127.0.0.1/tcp/7002\n"
                + "".join(f'{name}:\n  listen_address: "/ip4/127.0.0.1/tcp/{base + offset}"\n'
                          for name, offset in [("validator_network", 0), ("validator_network2", 1), ("validator_network3", 3)]))

    def test_delta_preserves_native_multipliers_and_independent_batching(self):
        for bound in (100, 200):
            profile = RAPTR.timing_profile(bound)
            self.assertEqual(profile["leader_timeout_ms"], 4 * bound)
            self.assertEqual(profile["partial_qc_wait_ms"], .1 * bound)
            self.assertEqual(profile["round_sync_interval_ms"], 15 * bound)
            self.assertEqual(profile["quorum_store_batch_poll_ms"], 150)
            self.assertEqual(profile["quorum_store_min_nonempty_batch_ms"], 80)
            self.assertEqual(profile["payload_wait_budget_ms"], 1500)
        for invalid in (0, -1, 60001, 0.1, True, "100"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                RAPTR.timing_profile(invalid)

    def test_ports_cover_all_native_validator_networks_and_exclude_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.yaml"
            path.write_text(self.config_text(24000))
            self.assertEqual(RAPTR.config_replica_ports(path), [24000, 24001, 24003])
            for bad in (self.config_text(24000).replace("validator_network3:", "other:"),
                        self.config_text(24000).replace("24003", "24001"),
                        self.config_text(24000).replace("127.0.0.1/tcp/24003", "0.0.0.0/tcp/24003")):
                path.write_text(bad)
                with self.assertRaises(RuntimeError):
                    RAPTR.config_replica_ports(path)

    def test_native_runtime_bound_must_be_observed_on_every_node(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for node in range(4):
                parent = Path(directory) / str(node)
                parent.mkdir()
                (parent / "log").write_text("RAPTR_BASELINE_TIMING delta_ms=100\n")
                paths.append(parent / "node.yaml")
            self.assertEqual(len(RAPTR.verify_native_timing(paths, 100)), 4)
            for bad in ("RAPTR_BASELINE_TIMING delta_ms=200\n", "no timing diagnostic\n"):
                (paths[2].parent / "log").write_text(bad)
                with self.assertRaises(RuntimeError):
                    RAPTR.verify_native_timing(paths, 100)

    def test_shaper_receives_actual_ports_and_archives_its_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/network_delay.py").write_text("# fixture helper\n")
            archive = root / "archive"
            archive.mkdir()
            paths = []
            for node in range(4):
                path = root / f"node-{node}.yaml"
                path.write_text(self.config_text(24100 + node * 10))
                paths.append(path)
            metadata = {"delay_ms": 10, "owned_anchor": "fixture"}
            client = SimpleNamespace(configure_from_environment=mock.Mock(return_value=metadata))
            manifest = {}
            with mock.patch.object(RAPTR, "ROOT", root), mock.patch.dict("sys.modules", network_delay=client):
                self.assertEqual(RAPTR.configure_network_shaping(paths, archive, manifest), metadata)
            expected = [24100 + node * 10 + offset for node in range(4) for offset in (0, 1, 3)]
            client.configure_from_environment.assert_called_once_with("raptr", expected)
            self.assertEqual(manifest["replica_network_ports"], expected)
            self.assertEqual(manifest["network_shaping"], metadata)
            self.assertTrue((archive / "network_delay.py").is_file())

    def test_shaping_is_between_readiness_and_warmup_and_cleared_after_scrape_error(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            source = archive / "native"
            (source / "target/release").mkdir(parents=True)
            for name in ("forge", "aptos-node"):
                (source / "target/release" / name).write_text("fixture binary")
            for node in range(4):
                parent = archive / "swarm" / str(node)
                parent.mkdir(parents=True)
                (parent / "node.yaml").write_text(self.config_text(24000 + node * 10))
                (parent / "log").write_text("RAPTR_BASELINE_TIMING delta_ms=100\n")
            args = SimpleNamespace(source=source, base_port=24000, nodes=4, rate=1000,
                                   startup=5, readiness_timeout=45, warmup=10, duration=30,
                                   transaction_bytes=512, ingress_batch_ms=100, delta_ms=100,
                                   setup_timeout=10)
            manifest = {"settings": {}, "commands": []}
            events = []
            process = SimpleNamespace(pid=33333, returncode=None, poll=mock.Mock(return_value=None),
                                      wait=mock.Mock(return_value=0))
            def launch(*args, **kwargs):
                (archive / "forge.log").write_text("num_clients 4\n")
                self.assertEqual(kwargs["env"]["RAPTR_DELTA_MS"], "100")
                return process
            def scrape(urls, path, phase):
                events.append(phase)
                if phase == "ready":
                    return [f"{COMPLETIONS} 1\n"] * 4, 1, .01
                raise RuntimeError("measurement scrape failed")
            def configure(*args):
                events.append("shape")
                return {"delay_ms": 10}
            def clear():
                events.append("clear")
                return {"cleared": True}
            members = [{"pid": 33334 + i, "executable": "/fixture/aptos-node"} for i in range(4)]
            with mock.patch.object(RAPTR, "verify_build_stamp", return_value={}), \
                 mock.patch.object(RAPTR, "check_ports"), \
                 mock.patch.object(RAPTR.subprocess, "Popen", side_effect=launch), \
                 mock.patch.object(RAPTR, "process_group_members", side_effect=[members, []]), \
                 mock.patch.object(RAPTR, "signal_owned_group"), \
                 mock.patch.object(RAPTR, "snapshot", side_effect=scrape), \
                 mock.patch.object(RAPTR, "configure_network_shaping", side_effect=configure), \
                 mock.patch.object(RAPTR, "clear_network_shaping", side_effect=clear), \
                 mock.patch.object(RAPTR.time, "sleep", side_effect=lambda value: events.append(f"sleep{value}")):
                with self.assertRaisesRegex(RuntimeError, "measurement scrape failed"):
                    RAPTR.run_benchmark(args, {}, archive, manifest)
            self.assertEqual(events, ["ready", "shape", "sleep10", "start", "clear"])
            self.assertEqual(manifest["network_shaping_cleanup"], {"cleared": True})


class RaptrCleanupTests(unittest.TestCase):
    def setUp(self):
        self.process = SimpleNamespace(pid=32100)
        self.child = {"pid": 32101, "executable": "/fixture/aptos-node"}
        self.members = mock.patch.object(RAPTR, "process_group_members").start()
        self.killpg = mock.patch.object(RAPTR.os, "killpg").start()
        self.kill = mock.patch.object(RAPTR.os, "kill").start()
        self.addCleanup(mock.patch.stopall)

    def test_natural_exit_leaves_an_empty_group_that_needs_no_signal(self):
        self.members.return_value = []
        RAPTR.signal_owned_group(self.process, signal.SIGTERM)
        self.killpg.assert_not_called()
        self.kill.assert_not_called()

    def test_group_disappearing_during_cleanup_is_harmless(self):
        self.members.return_value = [self.child]
        self.killpg.side_effect = ProcessLookupError("already exited")
        RAPTR.signal_owned_group(self.process, signal.SIGTERM)
        self.kill.assert_not_called()

    def test_macos_empty_group_permission_error_does_not_mask_run_failure(self):
        self.members.side_effect = [[self.child], []]
        self.killpg.side_effect = PermissionError("empty process group")
        RAPTR.signal_owned_group(self.process, signal.SIGTERM)
        self.kill.assert_not_called()

    def test_permission_fallback_targets_only_remaining_owned_processes(self):
        exited = {"pid": 32102, "executable": "/fixture/aptos-node"}
        self.members.side_effect = [[self.child, exited], [self.child]]
        self.killpg.side_effect = PermissionError("group signal refused")
        RAPTR.signal_owned_group(self.process, signal.SIGKILL)
        self.kill.assert_called_once_with(32101, signal.SIGKILL)

    def test_real_child_permission_failure_is_not_reported_as_clean_shutdown(self):
        self.members.side_effect = [[self.child], [self.child]]
        self.killpg.side_effect = PermissionError("group signal refused")
        self.kill.side_effect = PermissionError("child still cannot be signalled")
        with self.assertRaises(PermissionError):
            RAPTR.signal_owned_group(self.process, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
