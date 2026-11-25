"""Price epoch 226's pinned-source retry with the epoch 292 bundle reservation."""

import datetime
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

STATE = Path("/var/lib/jetstreamer")
HELPER = STATE / "horizon226-suffix-v1/capacity-epoch229-demotion-v2.py"
FAILED = STATE / "horizon226-extract-v2/failed-decode-terminal-v303.json"
NODE = STATE / "horizon226-layered-range-release-726c38e5-v1/qualification.json"
STAGING = STATE / "horizon292-closed-appendvec-staging-v304"
STAGE_BYTES = 67_427_276_780
RESTAGING = STATE / "horizon292-closed-appendvec-staging-v308"
RESTAGE_UNIT = "foundation-292-closed-appendvec-staging-v308.service"
RESTAGE_START_SHA = "05f9ea6221c08de8991036312640271e4861e6a8010f0c8f8069b4cad90d1776"
RESTAGE_BYTES = 68 << 30
START_RESERVE = 8 << 30
PRODUCER_MEMORY = 6 << 30
BROKER_MEMORY = 1 << 30
ROOT_CAP = 160 << 30
CPUS = set(range(8, 14))


def toolkit():
    spec = importlib.util.spec_from_file_location("known_capacity", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.load_existing()


def staging_cost(ops, device, block):
    original_ref = ops.ref(STAGING / "staging-start.json")
    original = ops.bound(original_ref)
    restart = RESTAGING / "staging-start.json"
    if restart.is_file():
        predecessor = ops.props(original["unit"], ["ActiveState", "MainPID", "ControlGroup"])
        assert predecessor == {"ActiveState": "failed", "MainPID": "0", "ControlGroup": ""}
        assert not (Path("/sys/fs/cgroup/system.slice") / original["unit"]).exists()
        start_ref = ops.ref(restart)
        assert start_ref["sha256"] == RESTAGE_START_SHA
        start = ops.bound(start_ref)
        intent = ops.bound(start["intent"])
        assert start["schema"] == "foundation-epoch292-appendvec-restage-start-v1"
        assert intent["schema"] == "foundation-epoch292-appendvec-restage-intent-v1"
        assert start["epoch"] == intent["epoch"] == 292 and intent["prior_staging"] == original_ref
        unit, expected = intent["unit"], start["owner"]
        assert unit == expected["Id"] == RESTAGE_UNIT and intent["kernel_output_cap_bytes"] == RESTAGE_BYTES
        directory, target, cap = RESTAGING, Path(intent["output"]), RESTAGE_BYTES
    else:
        assert ops.props(RESTAGE_UNIT, ["ActiveState", "MainPID"]) == {"ActiveState": "inactive", "MainPID": "0"}
        start_ref, start = original_ref, original
        intent = ops.bound(start["intent"])
        assert intent["epoch"] == 292 and intent["stage_peak_bytes"] == STAGE_BYTES
        unit, expected = start["unit"], start["process"]
        directory, target, cap = STAGING, Path(intent["expected_bundle"]), STAGE_BYTES
    values = ops.props(unit, list(expected))
    assert target == directory / "bundle/epoch-292-closed-appendvecs.pax.zst"
    maximum = (cap + block - 1) // block * block
    if values["ActiveState"] == "active":
        assert values == expected and values["SubState"] == "running"
        partial = target.with_suffix(target.suffix + ".part")
        try:
            detail = partial.lstat()
        except FileNotFoundError:
            # Keep the full reservation when the stage has no observed local output.
            return start_ref, values, maximum, int(values["MemoryMax"])
        assert stat.S_ISREG(detail.st_mode) and detail.st_dev == device
        assert detail.st_size <= cap and detail.st_nlink == 1
        return start_ref, values, max(0, maximum - 512 * detail.st_blocks), int(values["MemoryMax"])
    assert values["ActiveState"] in ("inactive", "failed") and values["MainPID"] == "0"
    assert not (Path("/sys/fs/cgroup/system.slice") / unit).exists()
    # A drained producer has no remaining writes. Existing files are in statvfs.
    return start_ref, values, 0, 0


def inspect(cap, kit):
    assert os.geteuid() == 0 and __debug__
    ops = kit.ops
    completed, fleet_ref, fleet = cap.latest_accepted_fleet(kit)
    assert not any(row["epoch"] == 226 for row in fleet["active"])
    assert [(row["epoch"], row["state"]) for row in fleet["inventory"]["entries"]
            if row["epoch"] == 226] == [(226, "missing")]
    failure_ref = ops.ref(FAILED)
    failure = ops.bound(failure_ref)
    assert failure["schema"] == "foundation-epoch226-extraction-decode-failure-v1"
    assert failure["output_directory_empty"] and not failure["prefix_produced"]
    prior_units = {failure["producer"]["Id"]: failure["producer"], **failure["auxiliaries"]}
    for name, old in prior_units.items():
        assert ops.props(name, list(old)) == old

    native = {}
    guards = {}
    helper = kit.measure.source.helper
    device = Path("/").stat().st_dev
    for row in fleet["active"]:
        epoch = row["epoch"]
        prior = row["producer"]
        owner = helper.active_props(prior["Id"], prior["InvocationID"])
        assert owner["MainPID"] == prior["MainPID"] and epoch not in native
        assert not CPUS & helper.cpus(owner["AllowedCPUs"])
        native[epoch] = owner
        if owner["Id"] in cap.DEMOTION229_GUARDS:
            guard = cap.DEMOTION229_GUARDS[owner["Id"]]
            plan = ops.bound(ops.ref(guard.parent / "guard-plan.json"))
            assert epoch == 229 and Path(plan["filesystem"]).stat().st_dev != device
        else:
            guard = cap.GUARDS[epoch]
            assert epoch != 229, "unrecognized epoch 229 scratch device"
        guards[epoch] = kit.measure.source.growth_for(epoch, owner, guard)

    raw = subprocess.check_output(
        ["systemctl", "list-units", "--type=service", "--state=running,activating", "--no-pager",
         "--no-legend", "--plain", "horizon-qualify-*", "horizon-perf-*", "horizon-upload-*",
         "horizon-restore-*", "foundation-*-broker-*"], text=True, timeout=10,
    )
    assert {line.split()[0] for line in raw.splitlines() if line.strip()} == {
        owner["Id"] for owner in native.values()
    }
    fs = os.statvfs("/home/ubuntu/.jetstreamer-private")
    assert Path("/home/ubuntu/.jetstreamer-private").stat().st_dev == device
    stage_ref, stage, stage_disk, stage_memory = staging_cost(ops, device, fs.f_frsize)
    disk_guards = {epoch: row for epoch, row in guards.items() if epoch != 229}
    floor = max(row["floor_bytes"] for row in disk_guards.values())
    assert floor == cap.FLOOR
    protected = floor + helper.PUBLICATION_SCRATCH + stage_disk + sum(
        row["remaining_growth_bytes"] for row in disk_guards.values()
    )
    free = fs.f_bavail * fs.f_frsize
    memory = {
        k: int(v.split()[0]) * 1024
        for k, v in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        if k in ("MemTotal", "MemAvailable")
    }
    memory_available = memory["MemAvailable"] - memory["MemTotal"] // 10 - stage_memory - sum(
        max(0, int(row["MemoryMax"]) - int(row["MemoryCurrent"])) for row in native.values()
    )
    return dict(
        schema="foundation-epoch226-layered-extraction-fit-v1", epoch=226,
        sampled_at=datetime.datetime.now(datetime.UTC).isoformat(), fleet=fleet_ref, completion=completed,
        predecessor=failure_ref, node=ops.ref(NODE), live_units=native, guard_evidence=guards,
        approved_floor_bytes=floor, publication_workspace_bytes=helper.PUBLICATION_SCRATCH,
        stage_receipt=stage_ref, stage_owner=stage, stage_remaining_bytes=stage_disk,
        stage_remaining_memory_cap_bytes=stage_memory, free_bytes=free, protected_existing_bytes=protected,
        new_extraction_cap_bytes=ROOT_CAP, additional_start_reserve_bytes=START_RESERVE,
        disk_margin_bytes=free - protected - ROOT_CAP - START_RESERVE,
        uncommitted_memory_bytes=memory_available,
        memory_margin_bytes=memory_available - PRODUCER_MEMORY - BROKER_MEMORY,
        admitted=False, publication_authorized=False,
    )


if __name__ == "__main__":
    current, kit = toolkit()
    print(json.dumps(inspect(current, kit), indent=2))
