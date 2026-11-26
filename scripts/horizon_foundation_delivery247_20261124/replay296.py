"""Observe the guarded epoch 296 singleton during Foundation cadence."""

import hashlib
from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref
from replay252 import sealed


ORIGINAL_UNIT = "horizon-qualify-296-rooted-singleton-v1.service"
ORIGINAL_STATE = V / "horizon296-guarded-singleton-v1"
ORIGINAL_TERMINAL_SHA = "2dd34c57a0faa24b33cd4ac39ae1d0fe3fae69633b3dad0c45ec95e54bc4383c"
RETRY_STATE = V / "horizon296-full-retry-guard-v1"
RETRY = (RETRY_STATE / "cadence-registration.json").is_file()
UNIT = "horizon-qualify-296-full-retry-v1.service" if RETRY else ORIGINAL_UNIT
STATE = RETRY_STATE if RETRY else ORIGINAL_STATE
REGISTRATION = STATE / "cadence-registration.json"
ROOT = Path("/home/ubuntu/.jetstreamer-private") / (
    "qualification-296-full-retry-v1" if RETRY else "qualification-296-rooted-singleton-v1"
)


def registered():
    source = sealed(REGISTRATION)
    row = bound(source)
    assert (row["epoch"], row["unit"], row["run_root"]) == (296, UNIT, str(ROOT))
    assert row["canonical_publication_authorized"] is False
    if RETRY:
        terminal_ref = sealed(ORIGINAL_STATE / "terminal.json", ORIGINAL_TERMINAL_SHA)
        terminal = bound(terminal_ref)
        assert row["schema"] == "foundation-epoch296-full-retry-cadence-registration-v1"
        assert row["original_terminal"] == terminal_ref and terminal["guard_drained"]
        old = props(ORIGINAL_UNIT, ["ActiveState", "MainPID", "ControlGroup", "Job"])
        assert old["ActiveState"] in ("inactive", "failed") and old["MainPID"] == "0"
        assert old["ControlGroup"] == old["Job"] == ""
        profile = bound(sealed(row["profile"]["path"], row["profile"]["sha256"]))
        assert row["unit"] == profile["unit"] and row["run_root"] == profile["worker_root"]
        dossier = bound(profile["inputs"])
        assert row["node"] == dossier["node"] and row["worker"] == dossier["worker"]
        admission = bound(sealed(row["admission"]["path"], row["admission"]["sha256"]))
        assert admission["profile_sha256"] == row["profile"]["sha256"]
        assert admission["epoch"] == 296 and admission["publication_authorized"] is False
        guard = bound(sealed(row["active_guard"]["path"], row["active_guard"]["sha256"], native_receipt=True))
        assert guard["producer_invocation_id"] == row["invocation_id"]
        assert guard["producer"]["pid"] == row["main_pid"] and guard["producer_stop_enabled"]
        assert guard["trip_reason"] is None and guard["guard_sha256"] == profile["guard_binary"]["sha256"]
    return source, row


def config():
    if not REGISTRATION.is_file():
        return []
    _, row = registered()
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
    source, row = registered()
    gate = plan["gates"]["296"]
    references = [source, row["admission"], row["active_guard"]]
    if RETRY:
        references.extend((row["profile"], row["original_terminal"]))
    for evidence in references:
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
