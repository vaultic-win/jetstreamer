"""Bind the exact epoch 143 interval owner to an independent native exit receipt."""

import hashlib
import json
from pathlib import Path
import runpy
import sys

watch = runpy.run_path(str(Path(__file__).with_name("epoch141-hourly-exit.py")))
helper = watch["suffix"]
require = watch["require"]
ROOT = watch["ROOT"].with_name("epoch143-first-hourly-20261127-v1")
DEST = ROOT / "terminal-capture-v1"
UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
IID = "4514e85834c34152ae0ecfde8a42001d"
OWNER_SHA = "3e86e32a4e29029bd985a003e94a850d014ee9442a40a45009352577bf817bf8"
PROGRESS_SHA = "a348ae8195e1a34cebb1888edcd6464f947d5ebdb300cb79bd75a83090a8aeb8"
SOURCE_SHA = "ecd1a6b42ed43c524903c18048c37b9959e9d3c60ad3d6cdd5ea23aa7927167e"
START_MONOTONIC = "4179969166107"


def frozen():
    owner, owner_ref = helper.read(ROOT / "HELD_OWNER.json", 0)
    progress, progress_ref = helper.read(ROOT / "FIRST_PROTECTED_PROGRESS.json", 0)
    fit, fit_ref = helper.read(ROOT / "POST_GUARD_SCREEN.json", 0)
    plan, plan_ref = helper.read(ROOT / "ACTUAL_GUARD_PLAN.json", 0)
    contract, contract_ref = helper.read(ROOT / "contract-v1/LAUNCH_PROFILE.json", 0)
    source, source_ref = helper.read(ROOT / "inputs-v1/SOURCE_REFERENCE.json", 0)
    permit, _ = helper.file_ref(ROOT / "barrier/allow", 0)
    require(owner_ref["sha256"] == OWNER_SHA and progress_ref["sha256"] == PROGRESS_SHA
            and source_ref["sha256"] == SOURCE_SHA and source_ref == contract["source_reference"]
            and contract_ref == owner["contract"] and owner["unit"] == UNIT
            and owner["producer_invocation_id"] == progress["producer_invocation_id"]
            == fit["held_invocation"] == plan["invocation_id"] == IID
            and fit_ref == owner["post_guard_fit"] and plan_ref == owner["guard_plan"]
            and fit["memory_fits"] and fit["disk_fits"] and fit["guard_floor_fits"]
            and plan["minimum_free_bytes"] == fit["guard_floor_bytes"]
            and progress["held_owner"] == owner_ref and progress["producer_pid"] == owner["producer_pid"]
            and progress["transactions"] > 0 and owner["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            and permit["sha256"] == hashlib.sha256(IID.encode()).hexdigest()
            and source["terminal"]["slot"] == 61787631 and source["terminal"]["generation"] == 1634786651485428,
            "epoch 143 owner, protection or source changed")
    return owner, dict(actor=owner_ref, release=permit, postguard=fit_ref, first_progress=progress_ref,
                       guard_plan=plan_ref, contract=contract_ref, source=source_ref), source, contract


if __name__ == "__main__":
    require(sys.argv[1:] in (["check"], ["capture"]), "expected check or capture")
    owner, bindings, _, _ = frozen()
    expected = dict(RuntimeMaxUSec="8h", ExecMainStartTimestampMonotonic=START_MONOTONIC)
    print(json.dumps(watch["capture"](UNIT, owner, bindings, expected, DEST, sys.argv[1], epoch=143)), flush=True)
