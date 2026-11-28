"""Price native48 build phases against the existing focused-169 and serial build reservations."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

import stage_native48 as stage

GIB = 1 << 30
CORE = 1_000_000
HOURLY = stage.PACKAGE.parent / "horizon_epoch169_hourly_admission_20261123_v1" / "hourly.py"
HOURLY_SHA = "9984607003bd65d6ad1cd515a3d7b8ec6a6cb7b8329bd443b7e7c5b4518ee75b"
RESTORE_AVAILABLE_FLOOR = 786_326_978_560


def read_ref(ref):
    data = Path(ref["path"]).read_bytes()
    stage.require(hashlib.sha256(data).hexdigest() == ref["sha256"], f"changed input {ref['path']}")
    return json.loads(data)


def price(complete, donor, general, protocol, host):
    stage.require(complete["fits"] and donor["native_admission_eligible"] and
                  donor["fleet"] == complete["fleet"] and donor["credit_for_retirement"] == 0,
                  "incomplete or unjoined fleet price")
    stage.require(donor["producer_cpu_micros"] == 3 * CORE and donor["producer_memory"] == 68 * GIB and
                  donor["guard_cpu_micros"] == CORE and donor["guard_memory"] == GIB and
                  general["build_cpu_quota_micros"] == CORE and general["build_memory_bytes"] == 2 * GIB and
                  general["build_and_native_qualification_serial"], "original reservations changed")
    phases = protocol["phases"]
    cpu = max(p["actor_cpu_usec"] for p in phases)
    memory = max(p["gate_plan"]["actor_memory_max_bytes"] for p in phases)
    stage.require((cpu, memory) == (2 * CORE, 4 * GIB) and
                  all("CPUQuota=100%" in p["guard_argv"] and "MemoryMax=256M" in p["guard_argv"]
                      for p in phases), "original actor or native DATA guard changed")
    # Phase Root runs under 1 CPU / 1 GiB. Bootstrap originally uses two serially overlapping
    # cgroups (2 CPU / 256 MiB Root and 2 CPU / 512 MiB rustc or fixture).
    slots = {"consumer": {"focused_169": [cpu + CORE, memory + GIB // 4],
                          "serial": [CORE, GIB]},
             "operator_bootstrap": {"focused_169": [3 * CORE, 512 * (1 << 20)],
                                    "serial": [CORE, 256 * (1 << 20)]}}
    for charges in slots.values():
        cpu_f, ram_f = charges["focused_169"]
        cpu_s, ram_s = charges["serial"]
        stage.require(cpu_f <= donor["producer_cpu_micros"] and ram_f <= donor["producer_memory"] and
                      cpu_s <= general["build_cpu_quota_micros"] and ram_s <= general["build_memory_bytes"],
                      "allocation would consume an independent booking")
    stage.require(protocol["whole_work_cap_bytes"] == 8 * GIB and
                  protocol["maximum_growth_overshoot_bytes"] == 2 * GIB and
                  protocol["additional_OS_budget_required_bytes"] == GIB // 2, "original disk scope changed")
    work = protocol["whole_work_cap_bytes"] + protocol["maximum_growth_overshoot_bytes"]
    overhead = protocol["additional_OS_budget_required_bytes"]
    margin = donor["margin"] - work - overhead
    return {
        "schema": "horizon-native48-build-resource-quote-v1", "at": complete["recorded_unix_seconds"],
        "fleet": complete["fleet"], "paid_donor": donor, "phase_quotas_cpu_micros_and_bytes": slots,
        "original_focused_guard_reserved": {"cpu_micros": CORE, "memory_bytes": GIB},
        "complete_promised_cpu_micros": complete["complete_cpu_quota_micros"],
        "complete_promised_memory_bytes": complete["complete_memory_plus_reserve_bytes"],
        "physical_memory_bytes": host["total_memory_bytes"],
        "physical_cpu_micros": host["resources"]["actual_online_cpus"] * CORE,
        "actor_only_cpu_shortfall_without_donor": max(0, complete["complete_cpu_quota_micros"] +
            cpu - general["build_cpu_quota_micros"] - host["resources"]["actual_online_cpus"] * CORE),
        "actor_only_memory_shortfall_without_donor": max(0, complete["complete_memory_plus_reserve_bytes"] +
            memory - general["build_memory_bytes"] - host["total_memory_bytes"]),
        "home_build_and_control_charge_bytes": work + overhead, "home_remaining_bytes": margin,
        "conditional_arithmetic_fits": margin >= 0, "resident_memory_available": complete["available_memory_bytes"],
        "restore_available_floor": RESTORE_AVAILABLE_FLOOR,
        "restore_shortfall": max(0, RESTORE_AVAILABLE_FLOOR - complete["available_memory_bytes"]),
        "replay_named_units_seen_by_145_census": [p["actor_unit"] for p in phases
                                                  if p["actor_unit"].startswith("horizon-qualify")],
        "build_authorized": False, "restore_authorized": False, "resource_credit_bytes": 0,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("fit", type=Path)
    p.add_argument("projection", type=Path)
    args = p.parse_args()
    stage.require(stage.sha(HOURLY) == HOURLY_SHA, "hourly price source changed")
    hourly = runpy.run_path(str(HOURLY))
    native_ref = stage.bound(args.fit.resolve(strict=True))
    projection_ref = stage.bound(args.projection.resolve(strict=True))
    native = read_ref(native_ref)
    projection = read_ref(projection_ref)
    fleet = read_ref(native["fleet"])
    donor = hourly["price"](native, projection)
    host = read_ref({"path": str(hourly["OLD"] / "POST_GUARD_CAPACITY.json"), "sha256": hourly["OLD_CPU"]})
    result = price(native, donor, fleet["retry9_auxiliary_commitments"], stage.snapshot(), host)
    print(json.dumps(dict(result, fit=native_ref, projection=projection_ref), indent=2))


if __name__ == "__main__":
    main()
