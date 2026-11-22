"""Check the extra home-backed compiler allocation against the whole fleet."""
import json
import os
from pathlib import Path
import runpy
import sys
import time

out, source, group = map(Path, sys.argv[1:])
assert os.geteuid() == 0 and sys.flags.isolated and __debug__
expected_service = {
    "tools-v18-registered136": "horizon-incident-145-post-registered-build-v1.service",
    "tools-v20-prestart": "horizon-incident-145-fixture-rejoin-build-v1.service",
}
fixture_post = group.name == "horizon-incident-145-post-fixture-build-v1.service"
if fixture_post:
    assert source.parent.name in ("tools-v20-prestart", "tools-v20")
else:
    assert group.name == expected_service[source.parent.name]
assert group.parent.name == "horizonaudit.slice"
assert (group.parent / "cpu.max").read_text().split() == ["1200000", "100000"]
assert (group.parent / "cpu.idle").read_text().strip() == "1"
assert int((group.parent / "memory.high").read_text()) == 20 << 30
assert int((group.parent / "memory.max").read_text()) == 24 << 30
assert int((group.parent / "memory.current").read_text()) + (768 << 20) <= 20 << 30
assert int((group.parent / "pids.current").read_text()) + 128 <= int((group.parent / "pids.max").read_text())

native = json.loads((out / "before.json").read_bytes())
provider = runpy.run_path(str(source))
assert native["fits"] and native["resource_credit_bytes"] == 0 and native["complete_cpu_quota_micros"] == 64_000_000
assert 0 <= time.time() - native["recorded_unix_seconds"] <= 120
fleet, _ = provider["fleet_head"](native["fleet"])
assert native["candidate136"] == dict(cap=72 << 30, remaining=72 << 30, occupied=False, loan_micros=0, identity=None)
def floor(candidate):
    return provider["disk_budget"](native["original_aggregate_HOME_bytes"], candidate, native["bookings"], 145,
                                   native["survivors"], native["replacements"], native["active168_guard_floor"],
                                   native["closed_prestart_remaining"])[0]
ordinary = floor(native["candidate136"])
zero = floor(dict(native["candidate136"], remaining=0))
whole136 = zero + (72 << 30)
runtime = Path("/var/lib/jetstreamer/horizon_runtime_data")
sys.path.insert(0, str(runtime / "prefix140-status-cadence-20261122-v1/cadence-tools"))
from prefix140_storage import storage
prefix = storage()
assert prefix["registration"] == fleet["current_private_prefix140_obligation"]["registration"]
growth = prefix["remaining_DATA_growth_bytes"]
assert 0 <= growth <= 16 << 20
if source.parent.name in ("tools-v20-prestart", "tools-v20"):
    assert native["bounded_qualification"] is None
    assert ordinary == native["native_before_registered_floor"] and zero == native["zero_candidate_floor"]
    snapshots = (native["prefix_before"], native["prefix_after"], prefix)
    assert all(item["registration"] == prefix["registration"] and
               item["child"]["InvocationID"] == prefix["child"]["InvocationID"] for item in snapshots)
    recorded_growth = max(item["remaining_DATA_growth_bytes"] for item in snapshots[:2])
    assert recorded_growth == native["remaining_prefix140_bytes"]
    booked = provider["post145_floor"](ordinary, zero, native["candidate136"], recorded_growth)
    assert booked == native["complete_required_HOME_bytes"]
    protected = max(booked, provider["post145_floor"](ordinary, zero, native["candidate136"], growth))
else:
    assert ordinary == native["complete_required_HOME_bytes"]
    protected = max(whole136, ordinary) + growth
assert out.stat().st_dev == Path("/home/sol").stat().st_dev
fs = os.statvfs(out)
available = min(native["available_HOME_bytes"], fs.f_bavail * fs.f_frsize)
scratch, retained = 88 << 20, 24 << 20
if fixture_post:
    quote = json.loads((out / "build-mirrors.json").read_bytes())
    assert quote["native"] == native and quote["fleet"] == native["fleet"] and quote["mirrors_fit"]
    assert quote["admission_granted"] is False and quote["actual_mirror_writes"] == 0
    assert quote["resource_credit_bytes"] == 0
    available = min(available, quote["available_HOME_bytes"])
    audit_growth = max(quote[key]["remaining_DATA_growth_bytes"] for key in ("ready_growth_before", "ready_growth_after"))
    assert 0 <= audit_growth <= 256 << 20
    protected = max(protected + quote["missing_mirror_bytes"], quote["required_with_mirrors_bytes"]) + audit_growth
required = protected + scratch + retained
assert available >= required, (available, required)
assert native["available_memory_bytes"] >= native["required_available_memory_bytes"] + (768 << 20)
with (out / "build-reservation.json").open("x") as receipt:
    json.dump(dict(fleet=native["fleet"], prefix140=prefix, full_136_floor=whole136, scratch=scratch, retained=retained,
                   available=available, required=required, headroom=available-required, cpu=1, memory=768<<20, tasks=128), receipt)
    receipt.flush()
    os.fsync(receipt.fileno())
print("registered 145 build HOME margin", available-required, flush=True)
