"""Price the 136 prestart against the installed V17 provider and the ready audit."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
NATIVE = ROOT / "incident-replay-fit-20261121-v1/tools-v17"
CADENCE = ROOT / "prefix140-status-cadence-20261122-v1/cadence-tools"
ADAPTER = ROOT / "epoch166-retry10-delivery-20261121-v1/capacity-tools-bounded/publication-fit"
NATIVE_SEAL = "039534af05bc3bd1f0d54d196cbef5a13b89d24697d8789216faf7bde90f20b7"
CADENCE_SEAL = "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e"
PRICE = "924c72177d61b8340f8ff75caba72d4cfe5228df4b27111e56d2656a9d8d2aa8"
ADAPTER_SHA = "729ceda384e4def082967e24758f2e58f18f2d068ad41bae5358cf9cb60b5fb0"
CAP = 72 << 30


def require(value, reason):
    if not value:
        raise ValueError(reason)


def pin(path, expected):
    metadata = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == metadata.st_gid == 0 and metadata.st_nlink == 1
            and metadata.st_mode & 0o222 == 0 and metadata.st_size <= 32 << 20, str(path))
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, "changed deployed member " + str(path))
    return raw


def check_package(path, digest):
    seal = json.loads(pin(path / "deployment-seal-receipt.json", digest))
    require(seal["destination"] == str(path), "foreign sealed directory")
    for row in seal["members"]:
        require(Path(row["name"]).name == row["name"], "foreign member")
        pin(path / row["name"], row["sha256"])


def price(native, native_floor, prefix_before, prefix_after, disk_now, memory_total):
    candidate = native["candidate136"]
    require(candidate["cap"] == CAP and candidate["remaining"] == CAP
            and not candidate["occupied"] and native["complete_cpu_quota_micros"] == 64_000_000
            and native["resource_credit_bytes"] == native["stopped_generation_resident_credit_bytes"] == 0
            and native["replay_launch_authorized"] is False, "incompatible or occupied native reservation")
    require(prefix_before["registration"] == prefix_after["registration"]
            and prefix_before["child"] == prefix_after["child"]
            and prefix_before["complete_result"] == prefix_after["complete_result"], "prefix owner changed")
    for state in (prefix_before, prefix_after):
        require(0 <= state["remaining_DATA_growth_bytes"] <= state["maximum_HOME_allocation_bytes"] == 16 << 20
                and state["additional_cpu_quota_micros"] == state["additional_memory_bytes"] ==
                state["resource_credit_bytes"] == state["archive_staging_bytes"] == 0,
                "unbounded prefix growth or additional entitlement")
    prefix = max(s["remaining_DATA_growth_bytes"] for s in (prefix_before, prefix_after))
    # The payload keeps every absolute incumbent stop floor *before* adding the 72 GiB.
    # V17 also books those 72 GiB, so recompute without it on the very same measured trees.
    protected = max(native_floor, native["complete_required_HOME_bytes"] - CAP) + prefix
    available = min(disk_now, native["available_HOME_bytes"])
    require(memory_total >= native["complete_memory_plus_reserve_bytes"], "physical RAM changed")
    return dict(protected_raw_floor_bytes=protected, candidate_remaining_growth_bytes=CAP,
                complete_required_HOME_bytes=protected + CAP, available_HOME_bytes=available,
                disk_fits=available >= protected + CAP,
                memory_fits=native["available_memory_bytes"] >= native["required_available_memory_bytes"],
                complete_memory_plus_reserve_bytes=native["complete_memory_plus_reserve_bytes"],
                total_memory_bytes=memory_total, remaining_prefix140_bytes=prefix,
                unfenced_with_candidate_cpu_micros=68_250_000, new_resource_credit_bytes=0)


def inspect(path, digest, waiter, mode, provider):
    require(mode in ("preflight", "session"), "unknown writer mode")
    expected = dict(image=dict(path=str(NATIVE / "post-stop-fit"), sha256=PRICE),
                    seal=dict(path=str(NATIVE / "deployment-seal-receipt.json"), sha256=NATIVE_SEAL))
    require(provider == expected, "new fleet needs the explicit V17 plan")
    check_package(CADENCE, CADENCE_SEAL)
    check_package(NATIVE, NATIVE_SEAL)
    pin(ADAPTER, ADAPTER_SHA)
    sys.path.insert(0, str(CADENCE))
    from evidence import checked
    from retired_public_audit import observe_public
    from prefix140_storage import storage
    ref = dict(path=str(path), sha256=digest)
    fleet = checked(ref)
    prior_audit = checked(fleet["current_audit_progress"]["observation"])
    recorded = checked(fleet["current_home_cycle_capacity"])
    ready = fleet["active_ready_range_audit_obligation"]
    historical = fleet["continuing_audit_obligation"]
    require(historical["current_storage"]["pricing_basis_only"] is True
            and historical["current_storage"]["included_in_current_aggregate"] is False
            and historical["current_storage"]["remaining_DATA_growth_bytes"] == 18 << 30
            and ready["current_observation"] == fleet["current_audit_progress"]["observation"]
            and ready["current_storage"] == recorded["audit_storage"], "unbound audit transition")
    def audit():
        seen, paid, witness = observe_public(Path("/home/sol").stat().st_dev, historical)
        require(witness == recorded["audit_owner_witness"] and witness["native"]["ActiveState"] == "active"
                and seen["active_ready_workers"] == prior_audit["active_ready_workers"]
                and paid["output_budget"] == ready["current_storage"]["output_budget"]
                and paid["maximum_host_allocation_bytes"] == ready["maximum_output_allocation_bytes"] == 256 << 20,
                "changed ready audit controller, workers or HOME policy")
        return witness, seen["active_ready_workers"], paid
    first, workers, before_ready = audit()
    before = storage()
    require(waiter is None and mode == "preflight",
            "136 session requires the jointly registered, drained 145 prestart boundary")
    bridge = runpy.run_path(str(ADAPTER))
    native = json.loads(bridge["capture_provider"](NATIVE / "post-stop-fit", str(path), digest))
    require(native["fleet"] == ref and native["schema"] == "horizon-incident-replay-fit-v1"
            and 0 <= time.time() - native["recorded_unix_seconds"] < 120, "wrong native price")
    module = runpy.run_path(str(NATIVE / "post-stop-fit"))
    floor, _, _ = module["disk_budget"](native["original_aggregate_HOME_bytes"], dict(remaining=0),
        native["bookings"], 145, native["survivors"], native["replacements"], native["active168_guard_floor"],
        native["closed_prestart_remaining"])
    last, last_workers, after_ready = audit()
    after = storage()
    require(first == last and workers == last_workers, "audit changed during native fit")
    disk = os.statvfs("/home/sol")
    total = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) * 1024
    result = price(native, floor, before, after, disk.f_bavail * disk.f_frsize, total)
    return dict(result, schema="horizon-136-writer-joint-fit-v1", fleet=ref, provider_seal=expected["seal"],
                authoritative_joint_fit=native, audit=first, ready_workers=workers,
                ready_growth_before=before_ready, ready_growth_after=after_ready,
                prefix_before=before, prefix_after=after, waiting_candidate=waiter,
                activation_compatible=False, replay_launch_authorized=False,
                next_gate="successful V5e completion and exclusive prestart before V11")


if __name__ == "__main__":
    print(json.dumps(inspect(Path(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3]),
                             sys.argv[4], json.loads(sys.argv[5])), sort_keys=True))
