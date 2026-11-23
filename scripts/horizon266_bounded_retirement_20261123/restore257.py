"""Carry the admitted 257 cold owner through shared pricing and the coordinated observer."""
import os
from pathlib import Path
import time

from owners import CG, D, V, bound, props, ref

EVENT = D / "horizon257-v16-owner-fleet-a1/completion.json"
EVENT_SHA = "6e277bee4a39a682b8d7c7e225518c1fe93e4c3e885a289df072b36f96d4d18c"
UNIT = "horizon-257-native-input-20261120-v1.service"
GUARD = "horizon-native257-protective-v1.service"
TIMER = "horizon-native257-protective-v1.timer"
TERMINAL = D / "horizon257-v16-terminal-a1/completion.json"


def evidence():
    event = ref(EVENT)
    assert event["sha256"] == EVENT_SHA
    record = bound(event)
    origin = bound(record["metadata_event"])
    h = bound(origin["startup_handoff"])
    assert h["unit"] == UNIT and h["invocation_id"] == origin["invocation_id"]
    assert h["main_pid"] == origin["main_pid"] and h["cpu_affinity"] == list(range(8))
    ad = bound(h["admission"])
    r = bound(ad["review"])
    award = bound(r["closed266_booking"])
    assert r["closed266_booking"]["sha256"] == "c28b7b8e77ad679827338f883e5496c42f2d2de6a3a25cc44c7d3f38cf2862cb"
    assert award["memory"] == 121342177280 and award["disk"] == 256000000000 and not award["automatic_release"]
    assert bound(h["first_guard_token"])["invocation_id"] == h["invocation_id"]
    return record, origin, h


def running(h):
    current = props(UNIT, ["InvocationID", "MainPID", "ActiveState", "ControlGroup", "Job"])
    assert current["InvocationID"] == h["invocation_id"] and not current["Job"]
    if current["ActiveState"] == "active":
        assert current["MainPID"] == str(h["main_pid"]) and current["ControlGroup"] == "/system.slice/" + UNIT
        assert os.sched_getaffinity(h["main_pid"]) == set(range(8))
        return True
    assert current["ActiveState"] in ("inactive", "failed") and current["MainPID"] == "0"
    assert not current["ControlGroup"] and not (CG / UNIT).exists()
    return False


def price_owner(assessment_only):
    _, _, h = evidence()
    if not running(h):
        return {}
    assert assessment_only, "live 257 is funded by the closed 266 assessment"
    return {UNIT: (h["invocation_id"], h["main_pid"], 120000000000, set(range(8)))}


def priced_services(enumerate_services):
    units = enumerate_services()
    if GUARD in units:
        _, _, h = evidence()
        g = props(GUARD, ["FragmentPath", "DropInPaths", "TriggeredBy"])
        assert Path(g["FragmentPath"]).resolve() == V / "horizon-native257-guard-units-cold-closed266-after-v218" / GUARD
        assert not g["DropInPaths"] and g["TriggeredBy"] == TIMER
        assert bound(h["guard_plan"])["invocation_id"] == h["invocation_id"]
        timer = props(TIMER, ["ActiveState", "Unit", "Job"])
        assert timer == dict(ActiveState="active", Unit=GUARD, Job="")
        time.sleep(0.3)
        units = enumerate_services()
    return units


def schedule(config, wrapper):
    _, origin, h = evidence()
    row = dict(epoch=257, unit=UNIT, expected_invocation_id=h["invocation_id"], main_pid=h["main_pid"],
               scratch_path=origin["private_run_root"], executable=h["harness"]["path"],
               executable_sha256=h["harness"]["sha256"])
    before = config.get("native_input_diagnostics", [])
    assert before in ([], [row]) and wrapper.get("native257_handoff") == (origin["startup_handoff"] if before else None)
    if running(h):
        config["native_input_diagnostics"] = [row]
        wrapper["native257_handoff"] = origin["startup_handoff"]
    else:
        config["native_input_diagnostics"] = []
        wrapper.pop("native257_handoff", None)


def fleet_predecessor(original):
    event, _, _ = evidence()
    live = bound(event["fleet"])
    if ref(original) == live["previous_fleet"]:
        return Path(event["fleet"]["path"])
    return original
