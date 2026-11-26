"""Track the private one-transaction epoch 296 warmup diagnostic."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


UNIT = "horizon-perf-epoch296-meter-bounded@v2.service"
STATE = V / "horizon296-meter-bounded-v2"
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-296-meter-bounded-v2")
PROFILE = STATE / "generic-unit-profile.json"
REGISTRATION = STATE / "cadence-registration.json"
TERMINAL = STATE / "terminal.json"
FIELDS = ("ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup")


def sealed(path):
    info = path.lstat()
    assert path.resolve() == path and path.is_file()
    assert info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
    return ref(path)


def registration():
    if not REGISTRATION.is_file():
        return None
    source = sealed(REGISTRATION)
    row = bound(source)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert (row["kind"], row["epoch"], row["unit"], row["run_root"]) == (
        "epoch296-private-meter-diagnostic", 296, UNIT, str(ROOT))
    assert row["launched"] and not row["remote_mutations"] and not row["r2_mutations"]
    assert row["canonical_epoch_publication_authorized"] is False
    profile = bound(sealed(PROFILE))
    assert row["profile"] == sealed(PROFILE) and row["worker"] == profile["worker"]
    admission = bound(row["admission"])
    assert admission["profile"] == row["profile"] and admission["admitted"]
    guard = bound(row["active_guard"])
    assert guard["producer_invocation_id"] == row["invocation_id"]
    assert guard["plan_sha256"] == row["guard_plan"]["sha256"] and guard["trip_reason"] is None
    assert guard["producer_stop_enabled"] and guard["producer"]["pid"] == row["main_pid"]
    return source, row


def configuration():
    registered = registration()
    if registered is None:
        return []
    _, row = registered
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["ActiveState"], live["SubState"], live["NRestarts"]) == ("active", "running", "0")
    assert live["InvocationID"] == row["invocation_id"] and int(live["MainPID"]) == row["main_pid"]
    assert live["ControlGroup"] == "/system.slice/" + UNIT
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node_path"])
    return [dict(range="296-296", controller_unit=UNIT, producer_unit=UNIT,
                 expected_controller_invocation_id=row["invocation_id"],
                 expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(ROOT), worker_executable_basename="historical-worker")]


def register(plan):
    if not PROFILE.is_file():
        return
    gate = plan["gates"]["296"]
    registered = registration()
    evidence = [sealed(PROFILE)]
    if registered is not None:
        source, row = registered
        if UNIT not in plan["tracked_units"]:
            plan["tracked_units"].append(UNIT)
        claim = dict(epoch=296, unit=UNIT, invocation_id=row["invocation_id"],
                     scratch_path=str(ROOT), launch_receipt=source)
        existing = [item for item in plan["diagnostics"] if item["unit"] == UNIT]
        assert not existing or existing == [claim]
        if not existing:
            plan["diagnostics"].append(claim)
        evidence.extend((source, row["admission"], row["active_guard"]))
        if TERMINAL.is_file():
            terminal = sealed(TERMINAL)
            closed = bound(terminal)
            assert closed["launch"] == source and closed["guard_drained"]
            evidence.append(terminal)
            gate["next_action"] = closed["next_action"]
        else:
            gate["next_action"] = "Collect the private meter trace and drain guards after its terminal result."
    else:
        gate["next_action"] = "Admit the bounded meter diagnostic against the complete live fleet."
    for item in evidence:
        if item not in gate["evidence"]:
            gate["evidence"].append(item)


def owns(row):
    if row.get("producer", {}).get("Id") != UNIT:
        return False
    _, launch = registration()
    assert row["epoch"] == 296 and row["phase"] == "diagnostic-qualification"
    assert row["producer"]["InvocationID"] == launch["invocation_id"]
    assert row["scratch_path"] == str(ROOT) and row["ordinary_replay_claim"] is False
    return True
