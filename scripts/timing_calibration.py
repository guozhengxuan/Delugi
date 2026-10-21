"""One acceptance rule for measured added RTT across benchmark backends.

This checks an established TCP echo path, not independent one-way delay. The
rule matches the October 19 isolated Linux check; old saved results are never
rewritten or promoted by this module.
"""
import math
import statistics

POLICY = "added-rtt-25pct-floor2ms-v1"


def nonnegative(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("RTT and delay values must be finite nonnegative numbers")
    return value


def addition(before_ms, configured_ms, delay_ms):
    before_ms, configured_ms, delay_ms = map(nonnegative, (before_ms, configured_ms, delay_ms))
    expected = 2 * delay_ms
    observed = configured_ms - before_ms
    tolerance = max(2, expected * .25)
    return {"policy": POLICY, "added_median_rtt_ms": observed,
            "expected_added_rtt_ms": expected, "acceptance_tolerance_ms": tolerance,
            "addition_matches": abs(observed - expected) <= tolerance}


def restored(before_ms, after_ms):
    return abs(nonnegative(after_ms) - nonnegative(before_ms)) <= 2


def sample_median(samples):
    if not isinstance(samples, list) or not 20 <= len(samples) <= 10000:
        raise ValueError("calibration requires 20..10000 raw RTT samples")
    return statistics.median([nonnegative(value) for value in samples])


def sample_record(row):
    if not isinstance(row, dict):
        raise ValueError("calibration sample record must be an object")
    median = sample_median(row.get("samples_ms"))
    if nonnegative(row.get("median_rtt_ms")) != median:
        raise ValueError("reported RTT median differs from raw samples")
    return median


def edge_records(rows, expected=None, require_roles=False):
    """Bind raw measurements to distinct directed peer/role identities."""
    if not isinstance(rows, list) or not 1 <= len(rows) <= 31 * 3:
        raise ValueError("calibration needs a bounded nonempty peer/role population")
    result = {}
    for row in rows:
        median = sample_record(row)
        edge = (row.get("source"), row.get("destination"), row.get("protocol_role_index", None if require_roles else 0))
        if (any(type(value) is not int or value < 0 for value in edge)
                or edge[0] == edge[1] or edge in result):
            raise ValueError("duplicate or invalid calibration peer/role identity")
        result[edge] = {"row": row, "median": median}
    if expected is not None and set(result) != set(expected):
        raise ValueError("RTT calibration lacks an exact committee ring")
    return result


def local_record(record, delay_ms):
    """Recompute acceptance from raw selected/control/before/after samples."""
    if nonnegative(record.get("requested_one_way_delay_ms")) != nonnegative(delay_ms):
        raise ValueError("calibration delay differs from requested preset")
    try:
        baseline, active, after, control_baseline, control, control_after = (
            sample_median(record[key]) for key in (
                "baseline_rtt_ms", "shaped_rtt_ms", "after_cleanup_rtt_ms",
                "control_baseline_rtt_ms", "control_rtt_ms", "control_after_cleanup_rtt_ms"))
    except KeyError as error:
        raise ValueError("calibration is missing raw before/configured/after or control samples") from error
    selected = addition(baseline, active, delay_ms)
    unselected = addition(control_baseline, control, 0)
    selected["returned_to_baseline"] = restored(baseline, after)
    unselected["returned_to_baseline"] = restored(control_baseline, control_after)
    return {"policy": POLICY, "selected": selected, "unselected_control": unselected,
            "passed": all(row["addition_matches"] and row["returned_to_baseline"]
                          for row in (selected, unselected)),
            "scope": "TCP echo added RTT; no independent one-way measurement"}
