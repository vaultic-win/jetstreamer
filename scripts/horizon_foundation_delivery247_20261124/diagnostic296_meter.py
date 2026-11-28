"""Track the private epoch 296 diagnostics and epoch 230 gap replay."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


LOADER = "loader-upgrade-focused-v2"
GAP = "short-gap-v1"
HOURLY_230 = "middle-hourly-first-v1"
SECOND_HOURLY_230 = "middle-hourly-second-v1"
FIRST_7871_230 = "first-7871-v1"
V1627_230 = "v1627-window-v1"
ADJACENT_230 = "adjacent-99445304-v1"
RESTORE = "native-restore-v1"
RESTORE_260 = "native-restore-260-v1"
OVERLAP_266 = "hourly-overlap-114929697-v1"
PREDECESSOR_266 = "original-predecessor-v1"
PREDECESSOR_266_PROFILE = V / "horizon266-original-predecessor-static-v1/profile.json"
PREDECESSOR_266_PROFILE_SHA = "7ed80c05ae0e1c706a271452d9b0dcb516c651fd0f97a2ec3f1c61a477a30f21"
PREDECESSOR_266_PREFLIGHT_SHA = "de5680f4fc6634529348c9701f639a66cf333c7296f69a7645dc97f1297bc4ae"
PREDECESSOR_266_CUSTODY = V / "horizon266-predecessor-intake-stage-v1/custody.json"
PREDECESSOR_266_CUSTODY_SHA = "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959"
WINDOW_266 = "window-114936474-v1"
WINDOW_266_UNIT = "horizon-qualify-checkpoint-continuation-266-window-114936474-v1.service"
WINDOW_266_ROOT = Path("/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114936474-v1")
WINDOW_266_PROFILE_SHA = "f7562054a31277bc38747652f9a79e6967b393d8713499e6998841390cb4c5d6"
WINDOW_266_PREFLIGHT_SHA = "9043e168fd2322c6c5e098bee42a40f69507fa9db7afd791ad59577354f3bed1"
TRACE = "loader-log-v3"
FEATURE_ACCOUNTS = "feature-account-v4"
FOCUSED = {
    LOADER: (296, "horizon296-loader-upgrade-focused-v2", "epoch296-private-loader-upgrade-diagnostic"),
    GAP: (230, "horizon230-short-gap-runtime-v1", "epoch230-private-short-gap"),
    HOURLY_230: (230, "horizon230-middle-hourly-first-runtime-v1", "epoch230-private-first-hourly-window"),
    SECOND_HOURLY_230: (230, "horizon230-middle-hourly-second-runtime-v1",
                        "epoch230-private-second-hourly-window"),
    FIRST_7871_230: (230, "horizon230-first-7871-runtime-v1", "epoch230-private-first-7871-window"),
    V1627_230: (230, "horizon230-v1627-replay-runtime-v1", "epoch230-private-v1627-window"),
    ADJACENT_230: (230, "horizon230-adjacent-99445304-runtime-v1", "epoch230-private-adjacent-99445304-window"),
    RESTORE: (258, "horizon258-native-restore-runtime-v1", "epoch258-private-native-restore"),
    RESTORE_260: (260, "horizon260-native-restore-runtime-v1", "epoch260-private-native-restore"),
    OVERLAP_266: (266, "horizon266-hourly-overlap-114929697-runtime-v1", "epoch266-private-hourly-overlap"),
    PREDECESSOR_266: (266, "horizon266-original-predecessor-runtime-v1", "epoch266-private-original-predecessor"),
    WINDOW_266: (266, "horizon266-window-114929698-114936474-runtime-v1", "epoch266-private-hourly-window"),
    TRACE: (296, "horizon296-loader-log-v3", "epoch296-private-loader-log-diagnostic"),
    FEATURE_ACCOUNTS: (296, "horizon296-feature-account-v4", "epoch296-private-feature-account-qualification"),
}
ATTEMPTS = ("v2", "v3", *FOCUSED)
FIELDS = ("ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup")


def attempt_paths(version):
    assert version in ATTEMPTS
    if version in FOCUSED:
        epoch, directory, _ = FOCUSED[version]
        if version == WINDOW_266:
            return WINDOW_266_UNIT, V / directory, WINDOW_266_ROOT
        suffix = RESTORE if version == RESTORE_260 else version
        return (f"horizon-qualify-{epoch}-{suffix}.service", V / directory,
                Path(f"/home/ubuntu/.jetstreamer-private/qualification-{epoch}-{suffix}"))
    unit = f"horizon-perf-epoch296-meter-bounded@{version}.service"
    state = V / f"horizon296-meter-bounded-{version}"
    root = Path(f"/home/ubuntu/.jetstreamer-private/qualification-296-meter-bounded-{version}")
    return unit, state, root


def profile_path(state, version):
    if version == PREDECESSOR_266:
        return PREDECESSOR_266_PROFILE
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
    if version == OVERLAP_266:
        assert row["predecessor_native_tuple_qualified"] is False
        assert row["cursor_normalization_qualified"] is False
    profile_ref = sealed(profile_path(state, version))
    profile = bound(profile_ref)
    assert row["profile"] == profile_ref and row["worker"] == profile["worker"]
    admission = bound(row["admission"])
    assert admission["profile"] == row["profile"] and admission["admitted"]
    guard = bound(row["active_guard"])
    assert guard["producer_invocation_id"] == row["invocation_id"]
    assert guard["plan_sha256"] == row["guard_plan"]["sha256"] and guard["trip_reason"] is None
    assert guard["producer_stop_enabled"] and guard["producer"]["pid"] == row["main_pid"]
    if version in (OVERLAP_266, PREDECESSOR_266):
        release = bound(row["guard_release_fit"])
        assert release["invocation_id"] == row["invocation_id"]
        assert release["roster"] == admission["roster"] and release["guard_plan"] == row["guard_plan"]
        if version == OVERLAP_266:
            assert row["lossless_restore"] == profile["restore_receipt"]
        else:
            assert profile_ref["sha256"] == PREDECESSOR_266_PROFILE_SHA
            assert profile["diagnostic_only"] and row["diagnostic_only"]
            assert row["predecessor_native_tuple_qualified"] is False
            assert row["cursor_normalization_qualified"] is False
            assert admission["preflight"] == {"path": str(state / "preflight.json"),
                                              "sha256": PREDECESSOR_266_PREFLIGHT_SHA}
            assert release["schema"] == "foundation-epoch266-original-predecessor-guard-release-fit-v1"
            assert release["publication_authorized"] is False
            custody = sealed(PREDECESSOR_266_CUSTODY)
            assert row["bootstrap_custody"] == custody
            assert custody["sha256"] == PREDECESSOR_266_CUSTODY_SHA
            evidence = bound(custody)
            assert evidence["profile"] == profile_ref and evidence["actual_readonly_projection_verified"]
    if version == WINDOW_266:
        release = bound(row["guard_release_fit"])
        plan = bound(row["node_plan"])
        assert profile_ref["sha256"] == WINDOW_266_PROFILE_SHA and profile["private"]
        assert row["bootstrap_custody"] == profile["bootstrap_custody"]
        assert admission["preflight"] == {"path": str(state / "preflight.json"),
                                          "sha256": WINDOW_266_PREFLIGHT_SHA}
        assert admission["schema"] == "foundation-epoch266-private-window-admission-v1"
        assert plan == dict(profile["node_plan_inputs"], admission=row["admission"],
                            minimum_free_bytes=admission["minimum_free_bytes"])
        assert release["schema"] == "foundation-epoch266-private-window-guard-release-fit-v1"
        assert release["invocation_id"] == row["invocation_id"] and release["node_plan"] == row["node_plan"]
        assert release["roster"] == admission["roster"] and release["guard_plan"] == row["guard_plan"]
        assert release["publication_authorized"] is False
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
            disposition_digests = {
                SECOND_HOURLY_230: "209c2d85e896a9e11dd61709ff403c7da82e3920c3b4997bbc0096cb82299b2a",
                FIRST_7871_230: "3e5ad33b99b32a39ebae808a7c4b9c4854e1cfd53d5ee73ec0257019fbd53828",
            }
            if version in disposition_digests:
                disposition = sealed(state / "terminal-cadence.json")
                assert disposition["sha256"] == disposition_digests[version]
                closed = bound(disposition)
                assert closed["terminal_receipt"] == terminal and closed["launch"] == source
                evidence.append(disposition)
            if not ordinary_replay:
                gate["next_action"] = closed["next_action"]
        elif not ordinary_replay:
            gate["next_action"] = (
                "Verify the restored accounts root and drain its guard."
                if version in (RESTORE, RESTORE_260) else
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
            if version in (RESTORE, RESTORE_260) else
            "Admit the checkpoint-bounded replay against the complete live fleet."
            if version in FOCUSED else
            "Admit the bounded meter diagnostic against the complete live fleet.")
    for item in evidence:
        if item not in gate["evidence"]:
            gate["evidence"].append(item)


def register(plan, ordinary_replay=False, include_focused=True):
    sample = bound(plan["observer"])
    ordinary_singletons = {
        epoch for epoch in (258, 260)
        if any(row["range"] == f"{epoch}-{epoch}"
               and row["invocation_binding_stable"]
               and row["producer_after"]["unit"] == f"horizon-qualify-{epoch}-singleton-v1.service"
               for row in sample["replays"])
    }
    for version in ATTEMPTS:
        if version in (PREDECESSOR_266, ADJACENT_230, WINDOW_266):
            continue
        epoch = FOCUSED.get(version, (296,))[0]
        ordinary = (epoch == 296 and ordinary_replay) or epoch in ordinary_singletons
        register_attempt(plan, version, ordinary, include_focused)


def register_predecessor_266(plan):
    # The caller binds the matching native fleet image before adding the claim.
    register_attempt(plan, PREDECESSOR_266, ordinary_replay=False, include_focused=True)


def register_adjacent_230(plan):
    register_attempt(plan, ADJACENT_230, ordinary_replay=False, include_focused=True)


def register_window_266(plan):
    register_attempt(plan, WINDOW_266, ordinary_replay=False, include_focused=True)


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
