"""Additional HOME obligations and native custody for the November 22 replay recovery."""
import hashlib
import os
from pathlib import Path
import runpy
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
STOPS = ROOT / "four-homefloor-20261122-v1/settlement-tools"
EVENT = ROOT / "four-homefloor-20261122-v1/R2_STOP_CORRECTIONS.json"
EVENT_SHA = "9719cca38d4d9f8fddb65529436c408139d884c1a7838b4ea323e39a8499a214"
CADENCE = ROOT / "prefix140-status-cadence-20261122-v1/cadence-tools"
MIRRORS = ROOT / "epoch136-joint-writer-20261122-v6/preflight-tools"


def settled(fleet, read, load):
    if fleet.get("current_four_homefloor_stops") != {"path": str(EVENT), "sha256": EVENT_SHA}:
        raise ValueError("fleet does not bind the four protective stops")
    load(STOPS, "eab84cd286c3fe52dcc037d4f1a1ad2313efec6321bad42861d2a07d41e37c74")
    stop = runpy.run_path(str(STOPS / "homefloor_stops.py"))
    proofs = {e: stop["verify"](e, "inspect") for e in stop["EPOCHS"]}
    handoff = read(fleet["survivor172_incident"])
    for epoch, proof in proofs.items():
        if read(proof["report"])["guard_stop_completion"] != handoff["closures"][str(epoch)]:
            raise ValueError("stop completion differs from the current fleet")
    return proofs


def validate_public(fleet, bound, audit, paid, witness, *, fresh_workers=False):
    ready = fleet["active_ready_range_audit_obligation"]
    home = bound(fleet["current_home_cycle_capacity"])
    observed = bound(ready["current_observation"])
    workers = audit["active_ready_workers"]
    if not (ready["current_observation"] == fleet["current_audit_progress"]["observation"] and
            ready["current_storage"] == home["audit_storage"] and witness == home["audit_owner_witness"] and
            witness["native"]["ActiveState"] == "active" and
            paid["output_budget"] == ready["current_storage"]["output_budget"] and
            paid["maximum_host_allocation_bytes"] == ready["maximum_output_allocation_bytes"] == 256 << 20 and
            ready["archive_staging_bytes"] == paid["remaining_archive_growth_bytes"] == 0):
        raise ValueError("public audit owner or HOME obligation changed")
    if not fresh_workers and workers != observed["active_ready_workers"]:
        raise ValueError("public readers changed since the fleet census")
    worker_ids = {(row["pid"], row["start_ticks"]) for row in workers}
    ranges = {tuple(row["range"]) for row in workers}
    if len(worker_ids) != len(workers) or len(ranges) != len(workers):
        raise ValueError("duplicate public audit worker or range")
    if fresh_workers and (paid["resident_archive_bytes"] != 0 or
                          any(row["observed_over_cap_bytes"] != 0 for row in paid["host_allocation_groups"])):
        raise ValueError("public audit allocation exceeds its HOME obligation")


def obligations(fleet, ref, bound, load, *, fresh_workers=False):
    load(CADENCE, "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e")
    load(MIRRORS, "404c245db5060e54e24295cb54de1d60d5549f657fc288c2185c4c72612a8ee8")
    # The legacy Python loader checks .py members. This executable has no suffix.
    manifest = bound({"path": str(MIRRORS / "deployment-seal-receipt.json"),
                      "sha256": "404c245db5060e54e24295cb54de1d60d5549f657fc288c2185c4c72612a8ee8"})
    script = MIRRORS / "price-mirrors"
    row, = (m for m in manifest["members"] if m["name"] == script.name)
    if hashlib.sha256(script.read_bytes()).hexdigest() != row["sha256"]:
        raise ValueError("mirror reader changed")
    mirror = runpy.run_path(str(script))
    dev = Path("/home/sol").stat().st_dev
    if mirror["STORE"].stat().st_dev != dev:
        raise ValueError("mirror store is outside HOME")
    block = os.statvfs(mirror["STORE"]).f_frsize
    sys.path.insert(0, str(CADENCE))
    try:
        from prefix140_storage import storage
        from retired_public_audit import observe_public
        if any(Path(sys.modules[name].__file__).parent != CADENCE for name in ("prefix140_storage", "retired_public_audit")):
            raise ValueError("foreign HOME accounting module")
        inputs = [mirror["inspect_input"](path, digest, block) for path, digest in
                  ((mirror["DOWNLOAD"], mirror["DOWNLOAD_SHA"]), (Path(ref["path"]), ref["sha256"]))]
        prefix = storage()
        audit, paid, witness = observe_public(dev, fleet["continuing_audit_obligation"])
    finally:
        sys.path.pop(0)
    validate_public(fleet, bound, audit, paid, witness, fresh_workers=fresh_workers)
    if not (prefix["registration"] == fleet["current_private_prefix140_obligation"]["registration"] and
            0 <= prefix["remaining_DATA_growth_bytes"] <= prefix["maximum_HOME_allocation_bytes"] == 16 << 20 and
            prefix["resource_credit_bytes"] == prefix["additional_cpu_quota_micros"] == prefix["additional_memory_bytes"] == 0):
        raise ValueError("private prefix owner or HOME obligation changed")
    return dict(mirror_inputs=inputs, missing_mirror_bytes=sum(v["required_bytes"] for v in inputs),
                prefix=prefix, public_owner=witness, public_workers=audit["active_ready_workers"],
                public_storage=paid)
