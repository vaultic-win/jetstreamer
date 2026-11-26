"""Track the private epoch 296 warmup and loader diagnostics."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


LOADER = "loader-upgrade-focused-v2"
ATTEMPTS = ("v2", "v3", LOADER)
FIELDS = ("ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup")


def attempt_paths(version):
    assert version in ATTEMPTS
    if version == LOADER:
        return (f"horizon-qualify-296-{version}.service", V / f"horizon296-{version}",
                Path(f"/home/ubuntu/.jetstreamer-private/qualification-296-{version}"))
    unit = f"horizon-perf-epoch296-meter-bounded@{version}.service"
    state = V / f"horizon296-meter-bounded-{version}"
    root = Path(f"/home/ubuntu/.jetstreamer-private/qualification-296-meter-bounded-{version}")
    return unit, state, root


def profile_path(state, version):
    return state / ("profile.json" if version == LOADER else "generic-unit-profile.json")


def sealed(path):
    info = path.lstat()
    assert path.resolve() == path and path.is_file()
    assert info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
    return ref(path)


def registration(version):
    unit, state, root = attempt_paths(version)
    path = state / "cadence-registration.json"
    if not path.is_file():
        return None
    source = sealed(path)
    row = bound(source)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    kind = ("epoch296-private-loader-upgrade-diagnostic" if version == LOADER
            else "epoch296-private-meter-diagnostic")
    assert (row["kind"], row["epoch"], row["unit"], row["run_root"]) == (
        kind, 296, unit, str(root))
    assert row["launched"] and not row["remote_mutations"] and not row["r2_mutations"]
    assert row["canonical_epoch_publication_authorized"] is False
    profile_ref = sealed(profile_path(state, version))
    profile = bound(profile_ref)
    assert row["profile"] == profile_ref and row["worker"] == profile["worker"]
    admission = bound(row["admission"])
    assert admission["profile"] == row["profile"] and admission["admitted"]
    guard = bound(row["active_guard"])
    assert guard["producer_invocation_id"] == row["invocation_id"]
    assert guard["plan_sha256"] == row["guard_plan"]["sha256"] and guard["trip_reason"] is None
    assert guard["producer_stop_enabled"] and guard["producer"]["pid"] == row["main_pid"]
    return source, row


def active_configuration(version):
    unit, _, root = attempt_paths(version)
    registered = registration(version)
    if registered is None:
        return []
    _, row = registered
    live = props(unit, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["ActiveState"], live["SubState"], live["NRestarts"]) == ("active", "running", "0")
    assert live["InvocationID"] == row["invocation_id"] and int(live["MainPID"]) == row["main_pid"]
    assert live["ControlGroup"] == "/system.slice/" + unit
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node_path"])
    return [dict(range="296-296", controller_unit=unit, producer_unit=unit,
                 expected_controller_invocation_id=row["invocation_id"],
                 expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(root), worker_executable_basename="historical-worker")]


def configuration():
    active = [item for version in ATTEMPTS for item in active_configuration(version)]
    assert len(active) <= 1
    return active


def register_attempt(plan, version, ordinary_replay):
    unit, state, root = attempt_paths(version)
    profile = profile_path(state, version)
    if not profile.is_file():
        return
    gate = plan["gates"]["296"]
    registered = registration(version)
    evidence = [sealed(profile)]
    if registered is not None:
        source, row = registered
        if unit not in plan["tracked_units"]:
            plan["tracked_units"].append(unit)
        evidence.extend((source, row["admission"], row["active_guard"]))
        terminal_path = state / "terminal.json"
        if terminal_path.is_file():
            terminal = sealed(terminal_path)
            closed = bound(terminal)
            assert closed["launch"] == source and closed["guard_drained"]
            evidence.append(terminal)
            if not ordinary_replay:
                gate["next_action"] = closed["next_action"]
        elif not ordinary_replay:
            gate["next_action"] = (
                "Collect the bounded loader replay result and drain its guard."
                if version == LOADER else
                "Collect the private meter trace and drain guards after its terminal result.")
        claim = dict(epoch=296, unit=unit, invocation_id=row["invocation_id"],
                     scratch_path=str(root), launch_receipt=source)
        existing = [item for item in plan["diagnostics"] if item["unit"] == unit]
        assert not existing or existing == [claim]
        if ordinary_replay:
            assert terminal_path.is_file() and not active_configuration(version)
            if existing:
                plan["diagnostics"].remove(claim)
        elif version == LOADER:
            # The deployed fleet image accepts the historical @instance scope.
            # Keep this invocation in the observer and unit census until a
            # fleet image recognizes its exact systemd unit.
            assert not existing
        elif not existing:
            plan["diagnostics"].append(claim)
    elif not ordinary_replay:
        gate["next_action"] = (
            "Admit the checkpoint-bounded loader diagnostic against the complete live fleet."
            if version == LOADER else
            "Admit the bounded meter diagnostic against the complete live fleet.")
    for item in evidence:
        if item not in gate["evidence"]:
            gate["evidence"].append(item)


def register(plan, ordinary_replay=False):
    for version in ATTEMPTS:
        register_attempt(plan, version, ordinary_replay)


def owns(row):
    owner = row.get("producer", {}).get("Id")
    for version in ATTEMPTS:
        unit, _, root = attempt_paths(version)
        if owner == unit:
            break
    else:
        return False
    _, launch = registration(version)
    assert row["epoch"] == 296 and row["phase"] == "diagnostic-qualification"
    assert row["producer"]["InvocationID"] == launch["invocation_id"]
    assert row["scratch_path"] == str(root) and row["ordinary_replay_claim"] is False
    return True
