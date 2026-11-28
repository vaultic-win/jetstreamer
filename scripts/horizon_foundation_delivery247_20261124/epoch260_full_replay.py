"""Admit the sealed epoch 260 singleton through the existing transient guard."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

V = Path("/var/lib/jetstreamer")
CONTROL = V / "horizon-seven-publication-controller-v222"
STATE = V / "horizon260-full-replay-runtime-v1"
HELPERS = V / "horizon296-meter-launcher-v3"
sys.path.append(str(HELPERS))
from epoch230_checkpoint_continuation_launch import activate_guarded, git, inventory, SOURCE
from epoch288_shrink_debt_comparison import load_existing

PROFILE_SHA = "00834c84f1b7bd2c20a2dc5ebd74a20626921a45e63438170adcbef8153c9193"
NAMESPACE_SHA = "34a65d591fba9d5a6f7a180d6965574cbf64dd7c20c3ac1104ddb8f512a46c36"
HOOK = dict(path=str(V / "horizon230-final-tail-tokens-v1/pre-start.sh"),
            sha256="14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0")
FIELDS = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup",
          "AllowedCPUs", "MemoryMax", "MemorySwapMax", "NRestarts", "Job")
ROSTER_SCHEMA = "foundation-epoch260-full-replay-roster-binding-v1"


def static_inputs(ops, rehash_bootstrap):
    ref = ops.ref(STATE / "profile.json")
    namespace_ref = ops.ref(STATE / "namespace.json")
    assert ref["sha256"] == PROFILE_SHA and namespace_ref["sha256"] == NAMESPACE_SHA
    profile, namespace = ops.bound(ref), ops.bound(namespace_ref)
    assert profile["schema"] == "foundation-epoch260-full-static-producer-profile-v1"
    assert profile["epoch"] == 260 and not profile["publication_authorized"]
    assert namespace["profile"] == ref and namespace["private_state_writable"]
    assert namespace["host_guard_sees_empty_placeholders"] and not namespace["worker_started"]
    inputs = ops.bound(profile["inputs"])
    for name in ("replay_node", "worker"):
        ops.checked_image(inputs[name])
    for name in ("manifest", "slot_ranges_override", "native_bootstrap_terminal"):
        ops.bound(inputs[name])
    guard = profile["guard"]
    ops.checked_image(guard)
    ops.checked_image(HOOK)
    template = ops.bound(profile["static_guard_plan"])
    validator = ops.bound(ops.ref(STATE / "static-guard-validation.json"))
    assert validator["validated"] and not validator["producer_signaled"]
    assert template["worker_root"] == profile["worker_root"] and template["unit"] == profile["unit"]
    assert template["maximum_root_physical_bytes"] == profile["maximum_root_physical_bytes"]
    bindings = []
    for spec, mount in zip(profile["readonly_bindings"], namespace["mounts"], strict=True):
        source, target = (Path(spec[key]) for key in ("path", "destination"))
        info = source.stat()
        assert source.resolve() == source and target.resolve() == target
        assert (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (
            spec["device"], spec["inode"], spec["bytes"], spec["mtime_ns"], spec["ctime_ns"])
        assert [mount[key] for key in ("destination", "device", "inode", "bytes")] == [
            spec[key] for key in ("destination", "device", "inode", "bytes")]
        assert target.stat().st_size == 0 and mount["mount_read_only"]
        if spec["path"] != inputs["bootstrap"]["path"] or rehash_bootstrap:
            with source.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == spec["sha256"]
            after = source.stat()
            assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        bindings.append(f"{source}:{target}")
    return ref, profile, inputs, template, bindings


def check_fit(kit, roster, profile):
    fit = roster["capacity"]
    assert roster["schema"] == ROSTER_SCHEMA and roster["epoch"] == 260
    assert not roster["admission_issued"] and not roster["candidate_held"]
    assert roster["full_replay_quote"]["inputs"] == profile["inputs"]
    assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 90
    assert fit["fits"] and fit["disk_shortfall_bytes"] == fit["memory_shortfall_bytes"] == 0
    assert fit["candidate_disk_bytes"] == profile["maximum_root_physical_bytes"] + profile["receipt_disk_reservation_bytes"]
    assert fit["candidate_total_memory_bytes"] == profile["maximum_memory_bytes"] + (1 << 30) + (256 << 20)
    assert fit["guard_floor_bytes"] == 3_770_104_987_645
    selected = kit.measure.source.helper.cpus
    assert selected(fit["cpus"]) == selected(profile["allowed_cpus"])
    listed = subprocess.check_output(
        ["systemctl", "list-units", "--type=service", "--state=running,activating",
         "--plain", "--no-legend", "--no-pager"], text=True, timeout=10)
    active = {line.split()[0] for line in listed.splitlines()
              if line.startswith(("horizon-", "foundation-", "archive-", "jetstreamer-"))}
    guards = {guard["unit"] for guard in roster["periodic_guards"].values()}
    assert active - guards == roster["owners"].keys()
    growth = fit["required_remaining_memory_bytes"]
    for unit, owner in roster["owners"].items():
        actual = kit.ops.props(unit, [*FIELDS, "MemoryCurrent"])
        assert all(actual[field] == owner["systemd"][field] for field in FIELDS)
        assert selected(profile["allowed_cpus"]).isdisjoint(selected(actual["AllowedCPUs"]))
        growth += max(0, owner["memory_current_bytes"] - int(actual["MemoryCurrent"]))
    for guard in roster["periodic_guards"].values():
        assert kit.ops.props(guard["timer"], ["ActiveState", "InvocationID", "Unit"]) == {
            "ActiveState": "active", "InvocationID": guard["timer_invocation_id"], "Unit": guard["unit"]}
    root = Path(profile["worker_root"])
    stat = os.statvfs(root)
    assert root.stat().st_dev == roster["filesystem_device"]
    free = stat.f_bavail * stat.f_frsize
    available, = (int(line.split()[1]) << 10 for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemAvailable:"))
    assert free >= fit["required_disk_bytes"] and available >= growth
    assert fit["required_hard_memory_bytes"] <= fit["host_total_memory_bytes"]
    return dict(free_bytes=free, available_memory_bytes=available, required_remaining_memory_bytes=growth,
                at_unix_seconds=int(time.time()))


def launch(kit, roster_ref):
    ops = kit.ops
    ref, profile, inputs, template, bindings = static_inputs(ops, rehash_bootstrap=False)
    roster = ops.bound(roster_ref)
    unit, guard = profile["unit"], profile["guard_unit"]
    assert not (STATE / "admission.json").exists()
    tokens = STATE / "tokens"
    assert not tokens.exists() and not any((STATE / "guard-receipts").iterdir())
    for name in (unit, guard, guard.removesuffix(".service") + ".timer"):
        assert ops.props(name, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    remote = inventory(kit, epoch=260, unit="foundation-260-full-replay-inventory")
    capacity = check_fit(kit, roster, profile)
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings), ReadOnlyPaths=str(tokens))
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    tokens.mkdir(mode=0o755)
    tokens.chmod(0o755)
    admission = ops.funds.put(STATE / "admission.json", {
        "schema": "foundation-epoch260-full-replay-admission-v1", "epoch": 260,
        "profile": ref, "roster": roster_ref, "fit": capacity, "inventory": remote,
        "guard_minimum_free_bytes": roster["capacity"]["guard_floor_bytes"],
        "publication_authorized": False,
    })
    owner, plan, token, active_guard = activate_guarded(
        kit, 260, STATE, tokens, unit, guard, profile["guard"], template, admission, props,
        f"ExecStartPre=/usr/bin/bash {HOOK['path']} 60 {tokens}", profile["argv"])
    iid = owner["invocation_id"]
    handoff = ops.funds.put(STATE / "handoff.json", {
        "producer": unit, "invocation_id": iid, "guard_plan": plan,
        "launch_token": token, "admission": admission, "ready": False,
    })
    registration = ops.funds.put(STATE / "cadence-registration.json", {
        "schema": "foundation-epoch260-replay-cadence-registration-v1", "epoch": 260,
        "unit": unit, "invocation_id": iid, "main_pid": owner["main_pid"], "run_root": profile["worker_root"],
        "profile": ref, "admission": admission, "handoff": handoff, "active_guard": active_guard,
        "worker": inputs["worker"], "ready": False, "publication_authorized": False,
    })
    return registration


def main():
    assert __debug__ and os.geteuid() == 0
    kit = load_existing()
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    os.umask(0o077)
    if sys.argv[1:] == ["--verify-inputs"]:
        ref, profile, _, _, aliases = static_inputs(kit.ops, rehash_bootstrap=True)
        print(json.dumps(dict(profile=ref, epoch=profile["epoch"], authenticated_aliases=len(aliases),
                              replay_launched=False, publication_authorized=False)))
        return
    path, digest = sys.argv[1:]
    roster_path = Path(path)
    assert roster_path.name == "roster.json" and roster_path.parent.parent == V
    assert roster_path.parent.name.startswith("horizon262-foundation-roster-")
    remote = git("rev-parse", "origin/account-updates").decode().strip()
    for path in (Path(__file__), CONTROL / "replay260.py"):
        assert path.read_bytes() == git("show", f"{remote}:{SOURCE / path.name}")
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        installation = kit.ops.bound(kit.ops.ref(STATE / "cadence-installation.json"))
        assert installation["epoch"] == 260
        assert installation["adapter"] == kit.ops.ref(CONTROL / "replay260.py")
        assert installation["registry"] == kit.ops.ref(CONTROL / "guarded_replays.py")
        print(json.dumps(launch(kit, dict(path=str(roster_path), sha256=digest))))


if __name__ == "__main__":
    main()
