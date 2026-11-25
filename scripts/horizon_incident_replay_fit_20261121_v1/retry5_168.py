"""Bind the stopped epoch 168 inputs and price a private replacement proposal."""
from bisect import bisect_left, bisect_right
from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from hashlib import file_digest, sha256
from math import ceil
from pathlib import Path
import argparse
import json
import os
import re


RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASIS = RUNTIME / "incident-replay-fit-20261121-v1"
OLD_BASE = RUNTIME / "epoch168-retry4-rebook-20261123-v1"
NEW_BASE = RUNTIME / "epoch168-retry5-rebook-20261125-v1"
OLD_ALIAS = Path("/run/horizon-full168-cold-v4")
NEW_ALIAS = Path("/run/horizon-full168-cold-v5")
GUARD_BASE = RUNTIME / "epoch168-cold-guard-20261125-v5"
LANE = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1")
OLD_RUN = LANE / "full-metered-20261121-v1/cold-retry4-20261123"
NEW_RUN = OLD_RUN.with_name("cold-retry5-20261125")
OLD_NAME = "168-full-metered-cold-v4-20261123"
NEW_NAME = "168-full-metered-cold-v5-20261125"
STOPPED_INVOCATION = "913443d7f9f44d7e9d3e0eec420acfab"
END = 73007999
REMAINING = 8963
GIB = 1 << 30
CAP = 512 * GIB
RUNWAY = 48 * GIB
FINALIZATION = 16 * GIB
STOP_LAG = 8 * GIB
WINDOW = 2000
TAIL_HOURS = 8
STOP_SAMPLE = OLD_BASE / "guard-receipts/sample-777fc5ad20bc4018a3cc19e3536223ee.json"
STOP_CONTROL = BASIS / "STOPPED168_RETRY5_RETAINED_SOURCE_CONTROL_20261125.json"
SOURCE_SHA = "488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2"
PREPARED_SHA = "91f4ba8df878b796e4a2a3735c5302791abde215a92638ca5bbaa4d4a71b65cc"
PAYLOAD_SHA = "490c8f5ddc6abfb1c73236de45b061bc57eded20ed698ae213a505575f3cd1e3"
FINGERPRINT = "sha256:f5824f170325f9def8fe257fd542c9093f298419b1f558d4c35ddd1a6ae98011"
V4_DROPIN_SHA = "962785e09604bb61d88ab2eeeedbf2a7f6975e28cd46c4f7c82553125180268e"
PROGRESS = re.compile(rb"^\[([^ ]+) INFO  jetstreamer_node\] progress slot (\d+)/73007999")


def need(test, message):
    if not test:
        raise ValueError(message)


def open_read(path):
    need(path.resolve(strict=True) == path, f"noncanonical path {path}")
    return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME), "rb")


def reference(path, raw):
    return {"path": str(path), "sha256": sha256(raw).hexdigest()}


def bound(path, digest):
    with open_read(path) as stream:
        raw = stream.read()
    ref = reference(path, raw)
    need(ref["sha256"] == digest, f"changed evidence {path}")
    return json.loads(raw), ref


def ref_data(ref):
    return bound(Path(ref["path"]), ref["sha256"])[0]


def identity(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def verified_member(path, digest, expected_identity=None, verify_content=True):
    with open_read(path) as stream:
        before = identity(os.fstat(stream.fileno()))
        if expected_identity is not None:
            need(before == expected_identity, f"changed retained identity {path}")
        if verify_content:
            need(file_digest(stream, "sha256").hexdigest() == digest, f"changed retained bytes {path}")
        need(before == identity(os.fstat(stream.fileno())) == identity(path.stat()),
             f"retained member changed during observation {path}")
    return {"path": str(path), "sha256": digest, "identity": before, "content_rehashed": verify_content}


def source_inputs(source, payload, rehash_bootstrap):
    live = ref_data(source["previous_live"])
    need(live["invocation_id"] == source["stop"]["producer_invocation_id"] == STOPPED_INVOCATION
         and live["manifest_fingerprint"] == FINGERPRINT and live["epoch_bounds"] == [72576000, END]
         and live["checkpoint"] == payload["root_checkpoint"] == source["checkpoint_source_metadata"]
         and source["checkpoint_bytes_verified"] is False,
         "different retry4 historical bank proof")
    need(source["resource_credit_bytes"] == source["stop"]["resource_credit_bytes"]
         == source["stop"]["reservation_ending_bytes"] == 0, "retained stop claims credit")
    intent = ref_data(source["stop"]["stop_intent"])
    stopped = ref_data(source["stop"]["terminal"])
    need(intent["reason"] == "root-physical-budget"
         and stopped["producer_invocation_id"] == STOPPED_INVOCATION
         and stopped["terminal"]["pid"] == 0 and stopped["terminal"]["active"] == "inactive"
         and stopped["scratch_deleted"] is False, "different retained retry4 guard stop")

    bootstrap = payload["bootstrap_file"]
    observed = source["bootstrap"]
    need((bootstrap["path"], bootstrap["sha256"], bootstrap["identity"][0], bootstrap["identity"][1],
          bootstrap["identity"][2], bootstrap["identity"][4], payload["bootstrap"]["generation"])
         == (observed["path"], observed["sha256"], observed["device"], observed["inode"],
             observed["bytes"], observed["ctime_ns"], observed["generation"]),
         "different pinned bootstrap")
    inputs = {"bootstrap": verified_member(Path(bootstrap["path"]), bootstrap["sha256"],
                                          bootstrap["identity"], rehash_bootstrap)}
    projections = [payload["genesis"], *(row["source"] for row in payload["indexes"])]
    inputs["genesis_and_indexes"] = [
        verified_member(Path(row["path"]), row.get("sha256"), row["identity"], verify_content=False)
        for row in projections
    ]
    members = {name: verified_member(Path(path), digest) for name, (path, digest) in payload["members"].items()}
    worker = source["worker"]
    worker_name = "jetstreamer-historical-worker-v1-5-6"
    need(members[worker_name]["path"] == worker["path"] and members[worker_name]["sha256"] == worker["sha256"]
         and [members[worker_name]["identity"][i] for i in (0, 1, 2, 4)]
         == [worker[key] for key in ("device", "inode", "bytes", "ctime_ns")], "changed retained worker")
    inputs["members"] = members
    inputs["boundary_manifest"] = source["boundary_manifest"]
    inputs["worker_deployment_seal"] = source["worker_deployment_seal"]
    ref_data(inputs["boundary_manifest"])
    ref_data(inputs["worker_deployment_seal"])
    need(members["preflight-168-v4.json"]["sha256"] == source["manifest"]["sha256"]
         and members["preflight-168-v4.json"]["path"] == source["manifest"]["path"], "changed retained manifest")
    return inputs, live, intent


def observed_tail(live, intent):
    log = Path(live["producer_log"]["path"])
    with open_read(log) as stream:
        current = os.fstat(stream.fileno())
        need((current.st_dev, current.st_ino) == (live["producer_log"]["device"], live["producer_log"]["inode"]),
             "changed retry4 producer log")
        tail_bytes = min(6_000_000, current.st_size)
        offset = current.st_size - tail_bytes
        raw_log = os.pread(stream.fileno(), tail_bytes, offset)
    stop_unix = STOP_SAMPLE.stat().st_mtime_ns // 10**9
    cutoff = stop_unix - TAIL_HOURS * 3600
    log_rows = []
    for line in raw_log.splitlines():
        match = PROGRESS.match(line)
        if match:
            epoch_time = datetime.fromisoformat(match[1].decode()).timestamp()
            if epoch_time >= cutoff - 50:
                log_rows.append((epoch_time, int(match[2])))
    need(log_rows[-1][1] == END - REMAINING and all(a <= b for a, b in zip(log_rows, log_rows[1:])),
         "changed retry4 tail progress")
    times = [row[0] for row in log_rows]
    samples = []
    for path in STOP_SAMPLE.parent.glob("sample-*.json"):
        observed_at = path.stat().st_mtime_ns / 10**9
        if not cutoff <= observed_at <= stop_unix + 1:
            continue
        with open_read(path) as stream:
            row = stream.read()
        value = json.loads(row)
        observation = value["root_physical_observation"]
        need(observation and value["producer_invocation_id"] == STOPPED_INVOCATION,
             f"foreign guard measurement {path}")
        # Receipt time is after both census passes. The producer log can be
        # at most one guard interval + stop latency behind the last sample.
        index = bisect_right(times, observed_at) - 1
        need(index >= 0 and 0 <= observed_at - times[index] < 50,
             f"guard observation {path} lacks nearby progress")
        samples.append((observed_at, observation["conservative_physical_bytes"],
                        log_rows[index][1], reference(path, row)))
    samples.sort()
    need(len(samples) >= 900 and samples[-1][3]["path"] == str(STOP_SAMPLE)
         and ref_data(samples[-1][3]) == intent["sample"], "incomplete retry4 tail census")
    return samples, {"path": str(log), "offset": offset, "length": len(raw_log),
                     "sha256": sha256(raw_log).hexdigest()}


def growth_price(source, samples, log):
    slots = [row[2] for row in samples]
    peak = (Fraction(0), None, None)
    for index, end in enumerate(samples):
        first = bisect_left(slots, end[2] - WINDOW, 0, index)
        for row in samples[max(0, first - 1):min(first + 2, index)]:
            distance = end[2] - row[2]
            if distance >= 1880:
                rate = Fraction(end[1] - row[1], distance)
                if rate > peak[0]:
                    peak = (rate, row, end)
    burst, before, after = max((b[1] - a[1], a, b) for a, b in zip(samples, samples[1:]))
    projection = ceil(peak[0] * REMAINING)
    observed = source["observed_growth_through_previous_stop_bytes"]
    historical_stop = samples[-1][1]
    need(historical_stop == source["stop"]["measured_physical_bytes"]
         and historical_stop - source["previous_initial_observation_bytes"] == observed,
         "retry4 physical growth does not reconcile")
    def quote_sample(row):
        return {"receipt_published_at_unix": row[0], "whole_tree_bytes": row[1],
                "nearby_replay_slot": row[2], "receipt": row[3]}
    retained = max(source["current_retained_tree_bytes"], historical_stop)
    minimum_increment = observed + RUNWAY + FINALIZATION + STOP_LAG
    need(0 < projection <= RUNWAY and 0 < burst <= STOP_LAG
         and retained + minimum_increment <= CAP, "retry5 cap no longer covers the retained replay basis")
    return {
        "whole_tree_guard_cap_bytes": CAP,
        "retained_baseline_charge_bytes": retained,
        "minimum_incremental_charge_bytes": minimum_increment,
        "incremental_headroom_to_cap_at_previous_stop_bytes": CAP - retained,
        "observed_replay_growth_through_stop_bytes": observed,
        "late_replay_runway_bytes": RUNWAY,
        "remaining_slots": REMAINING,
        "terminal_finalization_allowance_bytes": FINALIZATION,
        "guard_lag_allowance_bytes": STOP_LAG,
        "reserve_slack_at_previous_stop_bytes": CAP - retained - minimum_increment,
        "projection_bytes": projection,
        "projection_basis": [quote_sample(peak[1]), quote_sample(peak[2])],
        "peak_adjacent_positive_growth_bytes": burst,
        "burst_basis": [quote_sample(before), quote_sample(after)],
        "guard_sample_count": len(samples),
        "producer_log_bytes": log,
        "terminal_finalization_basis": (
            "The existing singleton route verifies the archived stream and publishes via same-mount rename. "
            "Its terminal root check compares the sealed manifest. A handoff snapshot export is absent. "
            "The allowance covers archive finishing, transactional metadata and additional late allocation."
        ),
        "qualification_basis": "Measured engineering estimate. Validate the guard and whole-host fit before a held start.",
    }


def proposed_profile(prepared, payload, old_payload_ref):
    profile = deepcopy(prepared["profile"])
    need(profile["payload"] == payload and prepared["payload"] == old_payload_ref
         and profile["payload_sha256"] == old_payload_ref["sha256"]
         and payload["whole_root"] == str(LANE) and payload["whole_root_cap"] == 288 * GIB
         and payload["producer_cpu_quota_percent"] == 900 and payload["producer_memory_max"] == 68 * GIB,
         "different retry4 deployed profile")
    def translate(value):
        if isinstance(value, list):
            return [translate(item) for item in value]
        if isinstance(value, dict):
            return {key: translate(item) for key, item in value.items()}
        if not isinstance(value, str):
            return value
        for old, new in ((OLD_RUN, NEW_RUN), (OLD_BASE, NEW_BASE), (OLD_ALIAS, NEW_ALIAS)):
            value = value.replace(str(old), str(new))
        return value.replace(OLD_NAME, NEW_NAME).replace("guarded-full168-cold-retry4", "guarded-full168-cold-retry5")

    profile = translate(profile)
    translated = profile["payload"]
    translated["whole_root_cap"] = CAP
    payload_sha = sha256((json.dumps(translated, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
    profile["payload_sha256"] = payload_sha
    profile["guard_binary_sha256"] = None
    profile["producer_argv"] = [
        "--setenv=HORIZON_FULL168_PAYLOAD_SHA256=" + payload_sha
        if arg.startswith("--setenv=HORIZON_FULL168_PAYLOAD_SHA256=") else arg
        for arg in profile["producer_argv"]
    ]
    need(translated["bootstrap_file"] == payload["bootstrap_file"]
         and translated["root_checkpoint"] == payload["root_checkpoint"]
         and translated["members"] == payload["members"]
         and translated["regular_node_argv"][-2:] == payload["regular_node_argv"][-2:]
         and translated["regular_node_argv"][-2] == "--cohort-manifest-fingerprint=" + FINGERPRINT
         and profile["producer_argv"][-8:] == translated["regular_node_argv"],
         "retry5 changed the pinned replay inputs")
    return profile


def namespace_dropin():
    directory = Path(__file__).resolve().parent.parent / "horizon_epoch168_full_metered_20261121_v1"
    prior = directory / "90-cold-retry4-home-namespace.conf"
    with open_read(prior) as stream:
        raw = stream.read()
    need(sha256(raw).hexdigest() == V4_DROPIN_SHA, "changed qualified retry4 common mount")
    translated = raw.decode().replace(str(OLD_RUN), str(NEW_RUN))
    need(translated.count(str(NEW_RUN)) == 2, "unexpected common mount translation")
    return {"source": reference(prior, raw), "contents": translated,
            "sha256": sha256(translated.encode()).hexdigest()}


def storage_review(native, native_ref, source):
    booking = native["bookings"]["168"]
    fleet = ref_data(native["fleet"])
    need(native["schema"] == "horizon-incident-replay-fit-v1" and native["epoch"] == 170
         and native["fits"] and native["candidate"] is None and native["normal168"] is None
         and not ({"168", "170"} & native["replacements"].keys())
         and native["stopped_cold168"] == source["stop"]
         and native["stopped_generation_resident_credit_bytes"] == native["resource_credit_bytes"] == 0
         and native["replay_launch_authorized"] is False
         and booking["measurement"] == "two complete stopped-tree walks"
         and booking["root"] == str(LANE) and booking["run"] == str(OLD_RUN)
         and booking["remaining_bytes"] == 0 and booking["cap_bytes"] == 288 * GIB
         and not ({168, 170} & {row["epoch"] for row in fleet["actual_executing_replays"]}),
         "native basis does not bind the stopped 168 resource obligations")
    retained = max(booking["physical_bytes"], source["stop"]["measured_physical_bytes"])
    need(retained <= CAP - source["observed_growth_through_previous_stop_bytes"]
         - RUNWAY - FINALIZATION - STOP_LAG, "retained tree no longer supports the proposed cap")
    remaining = CAP - retained
    available = min(native["available_HOME_bytes"], fleet["same_sample_conservative_free_DATA_bytes"])
    # Retain the entire existing quote, including competing producer promises.
    # Charge stop latency outside the guard cap as well as reserving it in the capacity model.
    required = native["complete_required_HOME_bytes"] + remaining + STOP_LAG
    return {
        "native_basis": native_ref, "fleet": native["fleet"],
        "basis_captured_unix": native["recorded_unix_seconds"],
        "observed_replay_epochs": sorted(row["epoch"] for row in fleet["actual_executing_replays"]),
        "native_home_required_bytes": native["complete_required_HOME_bytes"],
        "conservative_available_home_bytes": available,
        "retained_baseline_bytes": retained, "remaining_to_cap_bytes": remaining,
        "outside_cap_stop_allowance_bytes": STOP_LAG,
        "projected_home_required_bytes": required,
        "projected_home_margin_bytes": available - required,
        "sampled_storage_fit": available >= required,
        "candidate_cpu_quota_micros": 9000000,
        "candidate_memory_max_bytes": 68 * GIB,
        "native_complete_cpu_quota_micros": native["complete_cpu_quota_micros"],
        "native_memory_plus_reserve_bytes": native["complete_memory_plus_reserve_bytes"],
        "requires_new_candidate_bound_cpu_memory_and_guard_price": True,
    }


def build(rehash_bootstrap=False, native_basis=None):
    source, source_ref = bound(STOP_CONTROL, SOURCE_SHA)
    payload, payload_ref = bound(OLD_BASE / "COLD_PAYLOAD.json", PAYLOAD_SHA)
    prepared, prepared_ref = bound(OLD_BASE / "PREPARED.json", PREPARED_SHA)
    inputs, live, intent = source_inputs(source, payload, rehash_bootstrap)
    samples, log = observed_tail(live, intent)
    gate = Path(__file__).resolve().parent.parent / "horizon_epoch168_full_metered_20261121_v1/gate.py"
    with open_read(gate) as stream:
        gate_ref = reference(gate, stream.read())
    value = {
        "schema": "horizon-epoch168-retry5-candidate-v1",
        "epoch": 168, "recorded_unix_seconds": int(datetime.now().timestamp()),
        "source_control": source_ref, "retry4_preparation": prepared_ref,
        "inputs": inputs, "incremental_allocation": growth_price(source, samples, log),
        "profile": proposed_profile(prepared, payload, payload_ref),
        "home_namespace_dropin": namespace_dropin(),
        "gated_producer_source": gate_ref,
        "guard_enrollment": {
            "qualified_guard_receipt": str(GUARD_BASE / "GUARD_QUALIFIED.json"),
            "successor_root_receipt": str(NEW_BASE / "SUCCESSOR_ROOT.json"),
            "required_successor_root_fields": {
                "schema": "horizon-epoch168-retry5-successor-root-v1",
                "root": str(NEW_RUN), "device": 64512,
                "source_control_sha256": SOURCE_SHA, "whole_tree_cap_bytes": CAP,
            },
            "producer_guard_service": "horizon-guard-" + NEW_NAME + ".service",
            "producer_guard_receipts": str(NEW_BASE / "guard-receipts"),
        },
        "new_namespace": {"common_mount": str(NEW_RUN), "alias": str(NEW_ALIAS), "runtime": str(NEW_BASE)},
        "candidate_enrolled": False, "replay_launch_authorized": False, "resource_credit_bytes": 0,
    }

    if native_basis:
        native, native_ref = bound(Path(native_basis[0]), native_basis[1])
        value["storage_review"] = storage_review(native, native_ref, source)
    return value


if __name__ == "__main__":
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument("--rehash-bootstrap", action="store_true")
    options.add_argument("--native-basis", nargs=2, metavar=("ABSOLUTE_PATH", "SHA256"))
    args = options.parse_args()
    print(json.dumps(build(args.rehash_bootstrap, args.native_basis), sort_keys=True, indent=2))
