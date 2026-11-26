"""Track the private epoch 296 diagnostics and epoch 230 gap replay."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


LOADER = "loader-upgrade-focused-v2"
GAP = "short-gap-v1"
RESTORE = "native-restore-v1"
TRACE = "loader-log-v3"
FEATURE_ACCOUNTS = "feature-account-v4"
FOCUSED = {
    LOADER: (296, "horizon296-loader-upgrade-focused-v2", "epoch296-private-loader-upgrade-diagnostic"),
    GAP: (230, "horizon230-short-gap-runtime-v1", "epoch230-private-short-gap"),
    RESTORE: (258, "horizon258-native-restore-runtime-v1", "epoch258-private-native-restore"),
    TRACE: (296, "horizon296-loader-log-v3", "epoch296-private-loader-log-diagnostic"),
    FEATURE_ACCOUNTS: (296, "horizon296-feature-account-v4", "epoch296-private-feature-account-qualification"),
}
ATTEMPTS = ("v2", "v3", *FOCUSED)
FIELDS = ("ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup")


def attempt_paths(version):
    assert version in ATTEMPTS
    if version in FOCUSED:
        epoch, directory, _ = FOCUSED[version]
        return (f"horizon-qualify-{epoch}-{version}.service", V / directory,
                Path(f"/home/ubuntu/.jetstreamer-private/qualification-{epoch}-{version}"))
    unit = f"horizon-perf-epoch296-meter-bounded@{version}.service"
    state = V / f"horizon296-meter-bounded-{version}"
    root = Path(f"/home/ubuntu/.jetstreamer-private/qualification-296-meter-bounded-{version}")
    return unit, state, root


def profile_path(state, version):
    return state / ("profile.json" if version in FOCUSED else "generic-unit-profile.json")


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
    epoch, _, kind = FOCUSED.get(version, (296, None, "epoch296-private-meter-diagnostic"))
    assert (row["kind"], row["epoch"], row["unit"], row["run_root"]) == (
        kind, epoch, unit, str(root))
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
    epoch = row["epoch"]
    return [dict(range=f"{epoch}-{epoch}", controller_unit=unit, producer_unit=unit,
                 expected_controller_invocation_id=row["invocation_id"],
                 expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(root), worker_executable_basename="historical-worker")]


def configuration():
    active = [item for version in ATTEMPTS for item in active_configuration(version)]
    assert len({item["range"] for item in active}) == len(active)
    return active


def register_attempt(plan, version, ordinary_replay, include_focused):
    unit, state, root = attempt_paths(version)
    profile = profile_path(state, version)
    if not profile.is_file():
        return
    epoch = FOCUSED.get(version, (296,))[0]
    ordinary_replay = ordinary_replay and epoch == 296
    gate = plan["gates"][str(epoch)]
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
                "Verify the restored accounts root and drain its guard."
                if version == RESTORE else
                "Collect the bounded replay result and drain its guard."
                if version in FOCUSED else
                "Collect the private meter trace and drain guards after its terminal result.")
        claim = dict(epoch=epoch, unit=unit, invocation_id=row["invocation_id"],
                     scratch_path=str(root), launch_receipt=source)
        existing = [item for item in plan["diagnostics"] if item["unit"] == unit]
        assert not existing or existing == [claim]
        if ordinary_replay:
            assert terminal_path.is_file() and not active_configuration(version)
            if existing:
                plan["diagnostics"].remove(claim)
        elif not existing and (version not in FOCUSED or include_focused):
            plan["diagnostics"].append(claim)
    elif not ordinary_replay:
        gate["next_action"] = (
            "Admit the no-replay snapshot restore against the complete live fleet."
            if version == RESTORE else
            "Admit the checkpoint-bounded replay against the complete live fleet."
            if version in FOCUSED else
            "Admit the bounded meter diagnostic against the complete live fleet.")
    for item in evidence:
        if item not in gate["evidence"]:
            gate["evidence"].append(item)


def register(plan, ordinary_replay=False, include_focused=True):
    for version in ATTEMPTS:
        register_attempt(plan, version, ordinary_replay, include_focused)


def owns(row):
    owner = row.get("producer", {}).get("Id")
    for version in ATTEMPTS:
        unit, _, root = attempt_paths(version)
        if owner == unit:
            break
    else:
        return False
    _, launch = registration(version)
    assert row["epoch"] == launch["epoch"] and row["phase"] == "diagnostic-qualification"
    assert row["producer"]["InvocationID"] == launch["invocation_id"]
    assert row["scratch_path"] == str(root) and row["ordinary_replay_claim"] is False
    return True
