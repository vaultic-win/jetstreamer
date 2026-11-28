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
V14 = BASE / "public-audit73-observer-20261121-v1"
V14_PACKAGE = V14 / "observer-package"
V14_SEAL = "412c2d23437cdf3af6c5783f83489767709d5ab970420ade2c44bbc4dbbbe043"
FOLLOWING_PACKAGE = V14 / "following-observer-v2"
FOLLOWING_SEAL = "5c9a6bc8f123e67640a16b3a7d8712138110ae2aa744b0942e3f873ffed86d56"
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
    def members(package, digest):
        body = checked_bytes(package / "deployment-seal-receipt.json", digest)
        return {m["name"]: m for m in json.loads(body)["members"]}

    # The complete publisher imports its own 172-specific live owner modules.
    # Our audit-only call retains the original sealed native/evidence adapters.
    old = members(PACKAGE, SEAL)
    witness_package, witness_members, witness_seal = PACKAGE, old, SEAL
    for candidate, seal in ((V14_PACKAGE, V14_SEAL), (FOLLOWING_PACKAGE, FOLLOWING_SEAL)):
        if (candidate / "deployment-seal-receipt.json").exists():
            witness_package, witness_members, witness_seal = candidate, members(candidate, seal), seal
    for name in ("evidence", "owners", "audit_handoff", "public_witness"):
        filename = name + ".py"
        package, entries = (witness_package, witness_members) if name == "public_witness" else (PACKAGE, old)
        path = package / filename
        code = checked_bytes(path, entries[filename]["sha256"])
        module = types.ModuleType(name)
        sys.modules[name] = module
        exec(compile(code, str(path), "exec"), module.__dict__)
    observer = sys.modules["public_witness"]
    observer.deployment_sha256 = witness_seal
    return observer


def capture(observer, obligation):
    from evidence import checked, need, pair

    home = Path("/home/sol")
    incumbent = pair(CUT / "PUBLIC_OWNER.json", LAUNCH)
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
    launch = checked(owner["launch"])
    boundary = None
    if owner["launch"] != incumbent:
        need(observer.deployment_sha256 in (V14_SEAL, FOLLOWING_SEAL)
             and owner["launch"]["path"] == str(V14 / "PUBLIC_OWNER.json")
             and owner["previous_owner"] == incumbent, "unqualified public audit handoff")
        boundary = checked(owner["natural_epoch73_boundary"])
    need(row == launch["native"] == native.native()
         and native.ticks(launch["pid"]) == launch["start_ticks"], "different public audit owner")
    need(owner["shared_slice"]["CPUQuotaPerSecUSec"] == "4s", "shared audit CPU exceeds booking")
    for obs in (fleet, live):
        expected_pid = launch["pid"]
        if obs is fleet and boundary and obs["progress"]["pid"] != expected_pid:
            prior = checked(boundary["prior_fleet"])
            need(prior["continuing_audit_obligation"]["current_observation"]
                 == boundary["prior_audit_observation"] == obligation["current_observation"],
                 "fleet observation does not anchor the live handoff")
            expected_pid = checked(incumbent)["pid"]
        p = obs["progress"]
        need(obs["inventory"] == live["inventory"] and live["inventory"] is not None
             and obs["predecessor_stop"] == owner["predecessor_stop"]
             and p["schema"] == "horizon-r2-public-audit-progress-v1"
             and p["pid"] == expected_pid and p["remote_mutations"] is False
             and p["archive_scratch_bytes"] == 0, "fleet and live public audit differ")
    booked = obligation["current_storage"]
    need(booked["epoch"] == fleet["progress"]["epoch"]
         and booked == dict(storage, epoch=booked["epoch"])
         and all(type(booked[k]) is type(value) for k, value in storage.items()), "fleet and live storage obligations differ")
    owner.update(start_ticks=launch["start_ticks"], observer_seal=observer.deployment_sha256, inventory=live["inventory"])
    return owner


if __name__ == "__main__":
    print(json.dumps(capture(load_observer(), json.loads(sys.argv[1]))))
