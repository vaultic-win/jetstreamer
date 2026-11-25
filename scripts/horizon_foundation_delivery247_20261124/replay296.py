"""Observe the guarded epoch 296 singleton during Foundation cadence."""

import hashlib
from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


UNIT = "horizon-qualify-296-rooted-singleton-v1.service"
STATE = V / "horizon296-guarded-singleton-v1"
REGISTRATION = STATE / "cadence-registration.json"
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-296-rooted-singleton-v1")


def config():
    if not REGISTRATION.is_file():
        return []
    row = bound(ref(REGISTRATION))
    assert row["epoch"] == 296 and row["unit"] == UNIT and row["run_root"] == str(ROOT)
    assert row["canonical_publication_authorized"] is False
    live = props(UNIT, ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "NRestarts"])
    if live["ActiveState"] != "active" or live["SubState"] != "running":
        return []
    assert (live["InvocationID"], int(live["MainPID"])) == (row["invocation_id"], row["main_pid"])
    assert live["ControlGroup"] == "/system.slice/" + UNIT and live["NRestarts"] == "0"
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node"]["path"])
    group = Path("/sys/fs/cgroup") / live["ControlGroup"].lstrip("/")
    roots = []
    for pid in (group / "cgroup.procs").read_text().split():
        process = Path("/proc") / pid / "exe"
        try:
            worker = process.readlink()
        except FileNotFoundError:
            continue
        if worker.name != "historical-worker":
            continue
        assert worker.is_relative_to(ROOT) and worker.resolve(strict=True) == worker
        with process.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == row["worker"]["sha256"]
        scratch, = [path for path in worker.parents
                    if path.name == "scratch" and path.parent.parent.name == "root-cohort-296-296"]
        roots.append(scratch)
    if not roots:
        return []
    scratch, = roots
    return [dict(range="296-296", controller_unit=UNIT, producer_unit=UNIT,
                 expected_controller_invocation_id=row["invocation_id"],
                 expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(scratch), worker_executable_basename="historical-worker")]


def verify_replays(observed, configured):
    assert len(observed) == len(configured)
    if observed:
        seen, = observed
        expected, = configured
        assert seen["range"] == expected["range"] and seen["invocation_binding_stable"]
        assert seen["scratch_path"] == expected["scratch_path"]
        for role in ("controller", "producer"):
            identity = seen[f"{role}_after"]
            assert identity["unit"] == UNIT
            assert identity["invocation_id"] == expected[f"expected_{role}_invocation_id"]


def gate(plan, configured):
    if not REGISTRATION.is_file():
        return
    source = ref(REGISTRATION)
    row = bound(source)
    assert row["epoch"] == 296 and row["unit"] == UNIT
    gate = plan["gates"]["296"]
    for evidence in (source, row["admission"], row["active_guard"]):
        if evidence not in gate["evidence"]:
            gate["evidence"].append(evidence)
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    terminal = STATE / "terminal.json"
    if terminal.is_file():
        result = ref(terminal)
        closed = bound(result)
        assert not configured and closed["launch"] == source and closed["guard_drained"]
        assert closed["invocation_id"] == row["invocation_id"]
        if result not in gate["evidence"]:
            gate["evidence"].append(result)
        gate["state"] = "failed-needs-repair"
        gate["next_action"] = closed["next_action"]
    elif configured:
        gate["state"] = "staged-admissible"
        gate["next_action"] = "Track the guarded replay and verify the AccountsDb root at slot 128,303,325."
