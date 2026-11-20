"""Capture the same public audit owner used by the fleet's sealed observer."""
import hashlib
import json
from pathlib import Path
import sys
import types

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
CUT = BASE / "public-stream-observer-continuity-20261120-v1"
PACKAGE = CUT / "observer-package"
SEAL = "b0644414a36d7f46846c11ef9377a6e181f01e82be9829189432cde2ba481f44"
LAUNCH = "1990f8fe2c1c215586ad7c54980d2278ff937ce658588b5f6d321cd63ba04851"
HOME_START = "c043d9d42a50bd2aac7b1ab0c865f3a0ee1759fe6adc6da657aed4d5b5ad2257"


def checked_bytes(path, digest):
    with path.open("rb") as source:
        data = source.read((1 << 20) + 1)
    if len(data) > 1 << 20 or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"changed observer source {path}")
    return data


def load_observer():
    # Execute exactly the sealed bytes. Never import from the deployment's
    # directory or from its bytecode cache, even when running as root.
    seal = json.loads(checked_bytes(PACKAGE / "deployment-seal-receipt.json", SEAL))
    members = {m["name"]: m for m in seal["members"]}
    for name in ("evidence", "owners", "audit_handoff", "public_witness"):
        filename = name + ".py"
        path = PACKAGE / filename
        code = checked_bytes(path, members[filename]["sha256"])
        module = types.ModuleType(name)
        sys.modules[name] = module
        exec(compile(code, str(path), "exec"), module.__dict__)
    return sys.modules["public_witness"]


def capture(observer, obligation):
    from evidence import checked, need, pair

    home = Path("/home/sol")
    launch_ref = pair(CUT / "PUBLIC_OWNER.json", LAUNCH)
    launch = checked(launch_ref)
    start_ref = pair(BASE / "r2-audit-storage-20261119-v1/range-v9-transition/START_EVENT.json", HOME_START)
    start = checked(start_ref)
    native = observer.native
    expected = {
        "method": "public HTTP range playback",
        "home_storage_start_event": start_ref,
        "additional_memory_bytes": 24 << 30, "additional_cpu_quota_micros": 4_000_000, "tasks_max": 512,
        "DATA_storage_filesystem": str(home), "configured_free_floor_bytes": native.RESERVE,
        "working_allocation_cap_bytes": 16 << 30, "cargo_growth_allowance_bytes": 2 << 30,
        "archive_acceptance_ceiling_bytes": native.MAX_ARCHIVE,
        "archive_cap_is_acceptance_ceiling_not_reservation": True,
        "archive_staging_bytes": 0, "per_epoch_capacity_reserves_exact_archive_bytes": False,
        "original_promises_ended": False, "old166scratch_DATA_obligation_retained": 309237645312,
    }
    for key, value in expected.items():
        need(type(obligation.get(key)) is type(value) and obligation[key] == value,
             f"changed public audit obligation {key}")
    need("DATA_reservation_bytes" not in obligation and start["home_storage_active"] is True,
         "changed historical HOME obligation")
    fleet = checked(obligation["current_observation"])
    live, storage, owner = observer.observe_public(home.stat().st_dev, obligation)
    row = owner["native"]
    need(owner["launch"] == launch_ref and row == launch["native"] == native.native()
         and native.ticks(launch["pid"]) == launch["start_ticks"], "different public audit owner")
    need(owner["shared_slice"]["CPUQuotaPerSecUSec"] == "4s", "shared audit CPU exceeds booking")
    for obs in (fleet, live):
        p = obs["progress"]
        need(obs["inventory"] == live["inventory"] and live["inventory"] is not None
             and obs["predecessor_stop"] == owner["predecessor_stop"]
             and p["schema"] == "horizon-r2-public-audit-progress-v1"
             and p["pid"] == launch["pid"] and p["remote_mutations"] is False
             and p["archive_scratch_bytes"] == 0, "fleet and live public audit differ")
    booked = obligation["current_storage"]
    need(booked["epoch"] == fleet["progress"]["epoch"]
         and booked == dict(storage, epoch=booked["epoch"])
         and all(type(booked[k]) is type(value) for k, value in storage.items()), "fleet and live storage obligations differ")
    owner.update(start_ticks=launch["start_ticks"], observer_seal=SEAL, inventory=live["inventory"])
    return owner


if __name__ == "__main__":
    print(json.dumps(capture(load_observer(), json.loads(sys.argv[1]))))
