"""Bind the guarded epoch 262 producer to Foundation's existing cadence."""

import hashlib
import re
from pathlib import Path

from ordinary249.delivery248 import V, bound, props
from replay252 import sealed


UNIT = "horizon-qualify-262-singleton-v1.service"
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-262-singleton-v1")
STATE = V / "horizon262-full-guard-v1"
REGISTRATION = STATE / "cadence-registration.json"
PROFILE = V / "horizon262-full-profile-v1/profile.json"
PROFILE_SHA = "38418369187c04ed6d2166ec0ad3af7de0fbe1f0ac21ba369adf8c89a696c460"
FIELDS = ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "NRestarts"]


def evidence():
    source = sealed(REGISTRATION)
    receipt = bound(source)
    iid = receipt["invocation_id"]
    assert receipt["schema"] == "foundation-epoch262-replay-cadence-registration-v1"
    assert (receipt["epoch"], receipt["unit"], receipt["run_root"]) == (262, UNIT, str(ROOT))
    assert re.fullmatch("[0-9a-f]{32}", iid) and receipt["ready"] is False
    profile_ref = sealed(PROFILE, PROFILE_SHA)
    profile = bound(profile_ref)
    assert receipt["profile"] == profile_ref
    inputs = bound(profile["inputs"])
    admission_ref = receipt["admission"]
    admission = bound(sealed(admission_ref["path"], admission_ref["sha256"]))
    assert admission["epoch"] == 262 and admission["publication_authorized"] is False
    guard_ref = receipt["active_guard"]
    guard = bound(sealed(guard_ref["path"], guard_ref["sha256"], native_receipt=True))
    guard_plan = bound(sealed(guard["plan"], guard["plan_sha256"]))
    assert guard["producer_invocation_id"] == guard["producer"]["invocation_id"] == iid
    assert guard["producer"]["cgroup"] == f"/system.slice/{UNIT}"
    assert guard["producer"]["pid"] == receipt["main_pid"] and guard["producer"]["restarts"] == 0
    assert guard["trip_reason"] is None and guard["producer_stop_enabled"] is True
    assert guard["guard_sha256"] == profile["guard_binary"]["sha256"]
    assert (guard_plan["unit"], guard_plan["invocation_id"], guard_plan["worker_root"]) == (UNIT, iid, str(ROOT))
    assert guard_plan["maximum_root_physical_bytes"] == profile["maximum_root_physical_bytes"]
    return receipt, profile, inputs, (source, profile_ref, admission_ref, guard_ref)


def config():
    if not REGISTRATION.is_file():
        return []
    receipt, profile, inputs, _ = evidence()
    owner = props(UNIT, FIELDS)
    if (owner["ActiveState"], owner["SubState"]) != ("active", "running"):
        return []
    iid = receipt["invocation_id"]
    assert owner["InvocationID"] == iid and int(owner["MainPID"]) == receipt["main_pid"]
    assert owner["ControlGroup"] == f"/system.slice/{UNIT}" and owner["NRestarts"] == "0"
    proc = Path("/proc") / owner["MainPID"]
    assert (proc / "exe").samefile(inputs["replay_node"]["path"])
    assert (proc / "cmdline").read_bytes() == b"".join(arg.encode() + b"\0" for arg in profile["argv"])
    processes = Path("/sys/fs/cgroup") / owner["ControlGroup"].lstrip("/") / "cgroup.procs"
    scratch_paths = []
    for pid in processes.read_text().split():
        executable = Path("/proc") / pid / "exe"
        try:
            worker = executable.readlink()
        except FileNotFoundError:
            continue
        if worker.name == "historical-worker":
            assert worker.is_relative_to(ROOT) and worker.resolve(strict=True) == worker
            with executable.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == inputs["worker"]["sha256"]
            scratch, = (path for path in worker.parents
                        if path.name == "scratch" and path.parent.parent.name == "root-cohort-262-262")
            scratch_paths.append(scratch)
    if not scratch_paths:
        return []
    scratch, = scratch_paths
    assert props(UNIT, FIELDS) == owner
    return [dict(range="262-262", controller_unit=UNIT, producer_unit=UNIT,
                 expected_controller_invocation_id=iid, expected_producer_invocation_id=iid,
                 scratch_path=str(scratch), worker_executable_basename="historical-worker")]


def verify_replays(observed, configured):
    assert len(observed) == len(configured)
    for row, expected in zip(observed, configured, strict=True):
        assert row["range"] == expected["range"] and row["invocation_binding_stable"]
        assert row["scratch_path"] == expected["scratch_path"]
        for role in ("controller", "producer"):
            for end in ("before", "after"):
                identity = row[f"{role}_{end}"]
                assert identity["unit"] == UNIT and identity["restarts"] == 0
                assert identity["invocation_id"] == expected[f"expected_{role}_invocation_id"]


def gate(plan, configured):
    if not REGISTRATION.is_file():
        return
    _, _, _, sources = evidence()
    gate = plan["gates"]["262"]
    for source in sources:
        if source not in gate["evidence"]:
            gate["evidence"].append(source)
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    if configured:
        gate.update(state="staged-admissible",
                    next_action="Track the guarded epoch 262 replay through its terminal checkpoint.")
