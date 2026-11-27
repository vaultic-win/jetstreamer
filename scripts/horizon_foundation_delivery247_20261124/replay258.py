"""Check the guarded epoch 258 producer at the existing Foundation cadence."""

import hashlib
import re
from pathlib import Path

from ordinary249.delivery248 import V, bound, props
from replay252 import sealed


EPOCH = 258
UNIT = "horizon-qualify-258-singleton-v1.service"
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-258-singleton-v1")
STATE = V / "horizon258-full-replay-runtime-v1"
REGISTRATION = STATE / "cadence-registration.json"
HANDOFF = V / "horizon258-full-source-static-preparation-v1/integration.json"
HANDOFF_SHA = "4eeb953b99cd89fc5ea4ff26a3b60c2dbbbe109310398cbf41bcdcc15383ce67"
PROFILE = STATE / "profile.json"
CPUS = "48-55"
FIELDS = ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "NRestarts"]


def evidence():
    source = sealed(REGISTRATION)
    registration = bound(source)
    iid = registration["invocation_id"]
    assert registration["schema"] == "foundation-epoch258-replay-cadence-registration-v1"
    assert (registration["epoch"], registration["unit"], registration["run_root"]) == (EPOCH, UNIT, str(ROOT))
    assert re.fullmatch("[0-9a-f]{32}", iid) and registration["ready"] is False
    handoff_ref = sealed(HANDOFF, HANDOFF_SHA)
    handoff = bound(handoff_ref)
    assert handoff["epoch"] == EPOCH and handoff["admission_issued"] is False
    static = bound(handoff["profile"])
    assert static["allowed_cpus"] == static["properties"]["AllowedCPUs"] == static["properties"]["CPUAffinity"] == "56-63"
    expected = dict(static, allowed_cpus=CPUS,
                    properties=dict(static["properties"], AllowedCPUs=CPUS, CPUAffinity=CPUS))
    profile_ref = sealed(PROFILE, registration["profile"]["sha256"])
    profile = bound(profile_ref)
    assert registration["profile"] == profile_ref and profile == expected
    assert profile["inputs"] == handoff["source_recheck"]
    inputs = bound(profile["inputs"])["inputs"]
    assert registration["worker"] == inputs["worker"]

    admission_ref = registration["admission"]
    admission = bound(sealed(STATE / "admission.json", admission_ref["sha256"]))
    assert admission["schema"] == "foundation-epoch258-full-replay-admission-v1"
    assert admission["epoch"] == EPOCH and admission["publication_authorized"] is False
    assert admission["profile"] == profile_ref and admission_ref["path"] == str(STATE / "admission.json")
    fit = bound(sealed(admission["roster"]["path"], admission["roster"]["sha256"]))
    assert fit["schema"] == "foundation-epoch258-full-replay-roster-binding-v1" and fit["epoch"] == EPOCH
    assert fit["full_replay_quote"]["inputs"] == profile["inputs"]
    assert fit["full_replay_quote"]["sizing_reference"] == handoff_ref and fit["capacity"]["fits"]
    assert fit["capacity"]["cpus"].split() == [str(cpu) for cpu in range(48, 56)]
    assert fit["capacity"]["guard_floor_bytes"] == admission["guard_minimum_free_bytes"]

    proof = bound(sealed(registration["handoff"]["path"], registration["handoff"]["sha256"]))
    assert proof["producer"] == UNIT and proof["invocation_id"] == iid and proof["ready"] is False
    guard_ref = registration["active_guard"]
    guard = bound(sealed(guard_ref["path"], guard_ref["sha256"], native_receipt=True))
    plan = bound(sealed(guard["plan"], guard["plan_sha256"]))
    assert guard["producer_invocation_id"] == guard["producer"]["invocation_id"] == iid
    assert guard["producer"]["cgroup"] == f"/system.slice/{UNIT}"
    assert guard["producer"]["pid"] == registration["main_pid"] and guard["producer"]["restarts"] == 0
    assert guard["trip_reason"] is None and guard["producer_stop_enabled"] is True
    assert guard["guard_sha256"] == profile["guard"]["sha256"]
    assert (plan["unit"], plan["invocation_id"], plan["worker_root"]) == (UNIT, iid, str(ROOT))
    assert plan["maximum_root_physical_bytes"] == profile["maximum_root_physical_bytes"]
    assert plan["minimum_free_bytes"] == admission["guard_minimum_free_bytes"]
    return registration, profile, inputs, (source, profile_ref, admission_ref, guard_ref, handoff_ref)


def config():
    if not REGISTRATION.is_file():
        owner = props(UNIT, ["ActiveState", "MainPID", "ControlGroup", "Job"])
        assert owner == {"ActiveState": "inactive", "MainPID": "0", "ControlGroup": "", "Job": ""}
        return []
    registration, profile, inputs, _ = evidence()
    owner = props(UNIT, FIELDS)
    if owner["ActiveState"] in ("inactive", "failed"):
        assert owner["MainPID"] == "0" and not owner["ControlGroup"]
        assert owner["InvocationID"] in ("", registration["invocation_id"])
        return []
    assert (owner["ActiveState"], owner["SubState"], owner["NRestarts"]) == ("active", "running", "0")
    iid = registration["invocation_id"]
    assert owner["InvocationID"] == iid and int(owner["MainPID"]) == registration["main_pid"]
    assert owner["ControlGroup"] == f"/system.slice/{UNIT}"
    proc = Path("/proc") / owner["MainPID"]
    assert (proc / "exe").samefile(inputs["node"]["path"])
    assert (proc / "cmdline").read_bytes() == b"".join(arg.encode() + b"\0" for arg in profile["argv"])

    live = Path("/sys/fs/cgroup") / owner["ControlGroup"].lstrip("/") / "cgroup.procs"
    scratch_paths = []
    for pid in live.read_text().split():
        executable = Path("/proc") / pid / "exe"
        try:
            worker = executable.readlink()
        except FileNotFoundError:
            continue
        if worker.name != "historical-worker":
            continue
        assert worker.is_relative_to(ROOT) and worker.resolve(strict=True) == worker
        with executable.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == inputs["worker"]["sha256"]
        scratch, = (path for path in worker.parents
                    if path.name == "scratch" and path.parent.parent.name == "root-cohort-258-258")
        scratch_paths.append(scratch)
    assert props(UNIT, FIELDS) == owner
    if not scratch_paths:
        return []
    scratch, = scratch_paths
    return [dict(range="258-258", controller_unit=UNIT, producer_unit=UNIT,
                 expected_controller_invocation_id=iid, expected_producer_invocation_id=iid,
                 scratch_path=str(scratch), worker_executable_basename="historical-worker")]


def verify_replays(observed, configured):
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
        assert not configured
        return
    _, _, _, sources = evidence()
    gate = plan["gates"]["258"]
    for source in sources:
        match = [item for item in gate["evidence"] if item["path"] == source["path"]]
        assert not match or match == [source]
        if not match:
            gate["evidence"].append(source)
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    if configured:
        gate.update(state="staged-admissible",
                    next_action="Track the epoch 258 singleton through the canonical checkpoint and epoch close.")
