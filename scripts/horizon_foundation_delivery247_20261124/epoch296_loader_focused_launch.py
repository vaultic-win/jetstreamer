"""Admit the private checkpoint-bounded epoch 296 replay using the sealed guard."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time


V = Path("/var/lib/jetstreamer")
HELPERS = V / "horizon296-meter-launcher-v3"
sys.path.append(str(HELPERS))
from epoch288_shrink_debt_comparison import load_existing
from epoch230_checkpoint_continuation_launch import activate_guarded, git, inventory, SOURCE


STATE = V / "horizon296-loader-upgrade-focused-v2"
CONTROL = V / "horizon-seven-publication-controller-v222"
ADAPTER = "diagnostic296_meter.py"
UNIT = "horizon-qualify-296-loader-upgrade-focused-v2.service"
GUARD = "horizon-296-loader-upgrade-focused-protective-v2.service"
TOKENS = STATE / "tokens"
HOOK = {
    "path": str(V / "horizon230-final-tail-tokens-v1/pre-start.sh"),
    "sha256": "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0",
}
PROFILE = {
    "path": str(STATE / "profile.json"),
    "sha256": "f6318333fc088dee3c6109cb6434eba0fddb916ed6ed143bfd7ffca27a59beba",
}
PREFLIGHT = {
    "path": str(STATE / "preflight.json"),
    "sha256": "d93ae64c1058439379dafd6e9ffe3c1622ffaa9c8bbf8f16c8d505704c54e260",
}
RAM = 173_207_977_984
CAP = 160 << 30
RECEIPTS = 64 << 20
CPUS = "56-63"
FIELDS = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup",
          "AllowedCPUs", "MemoryMax")


def current_fit(kit, roster, root):
    ops = kit.ops
    fit = roster["capacity"]
    assert roster["schema"] == "foundation-epoch296-replay-roster-binding-v1"
    assert not roster["admission_issued"] and not roster["candidate_held"]
    assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 90
    assert roster["focused_296_quote"]["preflight"] == PREFLIGHT and fit["fits"]
    assert fit["candidate_disk_bytes"] == CAP + RECEIPTS
    assert fit["candidate_total_memory_bytes"] == RAM + (1 << 30) + (256 << 20)
    assert fit["guard_floor_bytes"] == 3_770_104_987_645
    cpus = kit.measure.source.helper.cpus
    assert cpus(fit["cpus"]) == cpus(CPUS)
    listing = subprocess.check_output(
        ["systemctl", "list-units", "--type=service", "--state=running,activating",
         "--plain", "--no-legend", "--no-pager"], text=True, timeout=10)
    live = {line.split()[0] for line in listing.splitlines()
            if line.startswith(("horizon-", "foundation-", "archive-", "jetstreamer-"))}
    guards = {row["unit"] for row in roster["periodic_guards"].values()}
    assert live - guards == roster["owners"].keys()
    growth = fit["required_remaining_memory_bytes"]
    for unit, row in roster["owners"].items():
        current = ops.props(unit, [*FIELDS, "MemoryCurrent"])
        assert all(current[key] == row["systemd"][key] for key in FIELDS)
        assert cpus(CPUS).isdisjoint(cpus(current["AllowedCPUs"]))
        growth += max(0, row["memory_current_bytes"] - int(current["MemoryCurrent"]))
    for guard in roster["periodic_guards"].values():
        row = ops.props(guard["timer"], ["ActiveState", "InvocationID", "Unit"])
        assert row == {"ActiveState": "active", "InvocationID": guard["timer_invocation_id"],
                       "Unit": guard["unit"]}
    filesystem = os.statvfs(root)
    assert root.stat().st_dev == roster["filesystem_device"]
    disk = min(filesystem.f_bavail * filesystem.f_frsize, fit["available_disk_bytes"])
    available_line, = (line for line in Path("/proc/meminfo").read_text().splitlines()
                       if line.startswith("MemAvailable:"))
    available = min(int(available_line.split()[1]) << 10, fit["available_memory_bytes"])
    assert disk >= fit["required_disk_bytes"] and available >= growth
    assert fit["required_hard_memory_bytes"] <= fit["host_total_memory_bytes"]
    return {"available_disk_bytes": disk, "available_memory_bytes": available,
            "required_remaining_memory_bytes": growth, "sampled_unix_seconds": time.time()}


def launch(kit, roster_ref):
    ops = kit.ops
    assert not (STATE / "admission.json").exists() and not TOKENS.exists()
    roster = ops.bound(roster_ref)
    preflight = ops.bound(PREFLIGHT)
    profile = ops.bound(PROFILE)
    for entry in preflight["evidence"]:
        assert ops.ref(Path(entry["path"])) == entry
    root = Path(profile["run_root"])
    writable = Path(profile["properties"]["ReadWritePaths"])
    runtime_state = Path(profile["environment"]["JETSTREAMER_PRIVATE_RUN_ROOT"])
    assert preflight["writable_private_state_validated"] and writable == root / "work"
    assert runtime_state.is_relative_to(writable) and runtime_state.is_dir()
    assert runtime_state.resolve() == runtime_state
    assert profile["unit"] == UNIT and profile["properties"]["AllowedCPUs"] == CPUS
    assert int(profile["properties"]["MemoryMax"]) == RAM
    assert profile["guarded_whole_tree_cap_bytes"] == CAP
    for name in ("node", "worker", "guard"):
        ops.checked_image(profile[name])
    node = profile["node"]["path"]
    hook = ops.checked_image(HOOK)
    namespace = ops.bound(ops.ref(STATE / "namespace.json"))
    bootstrap = ops.bound(ops.ref(STATE / "bootstrap-recheck.json"))["bootstrap"]
    assert namespace["profile"] == PROFILE and namespace["host_guard_sees_empty_placeholders"]
    bindings = []
    for binding, measured in zip(profile["readonly_bindings"],
                                 namespace["mounted_device_inode_size"], strict=True):
        source = Path(binding["path"])
        destination = Path(binding["destination"])
        info = source.stat()
        assert source.resolve() == source and destination.resolve() == destination
        assert destination.is_relative_to(root) and destination.stat().st_size == 0
        assert f"{info.st_dev}:{info.st_ino}:{info.st_size}" == measured
        bindings.append(f"{source}:{destination}")
    snapshot = Path(bootstrap["path"]).stat()
    assert bootstrap["identity"] == (
        f"{snapshot.st_dev}:{snapshot.st_ino}:{snapshot.st_size}:"
        f"{int(snapshot.st_mtime)}:{int(snapshot.st_ctime)}")
    template = ops.bound(profile["static_guard_plan"])
    assert template["unit"] == UNIT and template["worker_root"] == str(root)
    assert template["maximum_root_physical_bytes"] == CAP
    for directory in (root / "work/scratch", root / "work/tmp", STATE / "guard-receipts"):
        assert not any(directory.iterdir()), directory
    for unit in (UNIT, GUARD, GUARD.removesuffix(".service") + ".timer"):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    remote = inventory(kit, epoch=296, unit="foundation-296-focused-admission-inventory-v2")
    measured = current_fit(kit, roster, root)
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings),
                      ReadOnlyPaths=str(TOKENS), Delegate="no", OOMPolicy="kill",
                      UnsetEnvironment="HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY")
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    admission = ops.funds.put(STATE / "admission.json", {
        "schema": "foundation-epoch296-focused-admission-v1", "epoch": 296,
        "profile": PROFILE, "preflight": PREFLIGHT, "roster": roster_ref, "fit": measured,
        "inventory": remote, "admitted": True, "publication_authorized": False,
    })
    owner, plan, token, active_guard = activate_guarded(
        kit, 296, STATE, TOKENS, UNIT, GUARD, profile["guard"], template, admission,
        props, f"ExecStartPre=/usr/bin/bash {hook} 60 {TOKENS}", profile["argv"])
    return ops.funds.put(STATE / "cadence-registration.json", {
        "schema": "jetstreamer-historical-performance-launch-receipt-v1",
        "kind": "epoch296-private-loader-upgrade-diagnostic", "epoch": 296, "unit": UNIT,
        "run_root": str(root), "invocation_id": owner["invocation_id"], "main_pid": owner["main_pid"],
        "node_path": node, "worker": profile["worker"], "profile": PROFILE, "admission": admission,
        "guard_plan": plan, "launch_token": token, "active_guard": active_guard,
        "launched": True, "evidence": {"units": [owner]},
        "canonical_epoch_publication_authorized": False, "remote_mutations": False,
        "r2_mutations": False,
    })


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0 and len(sys.argv) == 3
    kit = load_existing()
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    os.umask(0o077)
    remote = git("rev-parse", "origin/account-updates").decode().strip()
    for path in (Path(__file__), CONTROL / ADAPTER):
        assert path.read_bytes() == git("show", f"{remote}:{SOURCE / path.name}")
    path = Path(sys.argv[1])
    assert path.parent.parent == V and path.name == "roster.json"
    assert path.parent.name.startswith("horizon262-foundation-roster-")
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        print(json.dumps(launch(kit, {"path": str(path), "sha256": sys.argv[2]}), indent=2))
