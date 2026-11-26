"""Admit a private checkpoint-bounded replay using the sealed guard."""

import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
import time


V = Path("/var/lib/jetstreamer")
HELPERS = V / "horizon296-meter-launcher-v3"
sys.path.append(str(HELPERS))
from epoch288_shrink_debt_comparison import load_existing
from epoch230_checkpoint_continuation_launch import activate_guarded, git, inventory, SOURCE


CONTROL = V / "horizon-seven-publication-controller-v222"
ADAPTER = "diagnostic296_meter.py"
HOOK = {
    "path": str(V / "horizon230-final-tail-tokens-v1/pre-start.sh"),
    "sha256": "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0",
}
FIELDS = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup",
          "AllowedCPUs", "MemoryMax")


@dataclass(frozen=True)
class Scope:
    epoch: int
    state: Path
    unit: str
    guard: str
    kind: str
    roster_schema: str
    profile_sha: str
    preflight_sha: str
    ram: int
    cap: int
    receipts: int
    cpus: str

    @property
    def profile(self):
        return {"path": str(self.state / "profile.json"), "sha256": self.profile_sha}

    @property
    def preflight(self):
        return {"path": str(self.state / "preflight.json"), "sha256": self.preflight_sha}


LOADER_296 = Scope(
    296, V / "horizon296-loader-upgrade-focused-v2",
    "horizon-qualify-296-loader-upgrade-focused-v2.service",
    "horizon-296-loader-upgrade-focused-protective-v2.service",
    "epoch296-private-loader-upgrade-diagnostic", "foundation-epoch296-replay-roster-binding-v1",
    "f6318333fc088dee3c6109cb6434eba0fddb916ed6ed143bfd7ffca27a59beba",
    "d93ae64c1058439379dafd6e9ffe3c1622ffaa9c8bbf8f16c8d505704c54e260",
    173_207_977_984, 160 << 30, 64 << 20, "56-63",
)
GAP_230 = Scope(
    230, V / "horizon230-short-gap-runtime-v1",
    "horizon-qualify-230-short-gap-v1.service", "horizon-230-short-gap-protective-v1.service",
    "epoch230-private-short-gap", "foundation-epoch230-short-gap-roster-binding-v1",
    "95aebc954169426d79663a297b8c445a9c3ca5b759a84fc96e51cd5f77313982",
    "1b9a96e850cb4b050f2f64ee90665399dbddc7c9b2a71fe5afb32796b2518dcb",
    225_000_000_000, 208 << 30, 256 << 20, "72-79",
)
RESTORE_258 = Scope(
    258, V / "horizon258-native-restore-runtime-v1",
    "horizon-qualify-258-native-restore-v1.service", "horizon-258-native-restore-protective-v1.service",
    "epoch258-private-native-restore", "foundation-epoch258-native-restore-roster-binding-v1",
    "1cc91a3e939dd93920ddc6efbd720b9f558b00b3f27d2b6d654362068d2af035",
    "ac7cef6418be874cf8437171323fa2f9f1c1cf84ce41917096df4c489f270c6d",
    160 << 30, 96 << 30, 64 << 20, "56-63",
)
SCOPED_ARGS = {"--epoch230": GAP_230, "--epoch258": RESTORE_258}


def current_fit(kit, roster, root, scope):
    ops = kit.ops
    fit = roster["capacity"]
    assert roster["schema"] == scope.roster_schema
    assert not roster["admission_issued"] and not roster["candidate_held"]
    assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 90
    assert roster[f"focused_{scope.epoch}_quote"]["preflight"] == scope.preflight and fit["fits"]
    assert fit["candidate_disk_bytes"] == scope.cap + scope.receipts
    assert fit["candidate_total_memory_bytes"] == scope.ram + (1 << 30) + (256 << 20)
    assert fit["guard_floor_bytes"] == 3_770_104_987_645
    cpus = kit.measure.source.helper.cpus
    assert cpus(fit["cpus"]) == cpus(scope.cpus)
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
        assert cpus(scope.cpus).isdisjoint(cpus(current["AllowedCPUs"]))
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


def launch(kit, roster_ref, scope):
    ops = kit.ops
    state = scope.state
    tokens = state / "tokens"
    assert not (state / "admission.json").exists() and not tokens.exists()
    roster = ops.bound(roster_ref)
    preflight = ops.bound(scope.preflight)
    profile = ops.bound(scope.profile)
    for name in ("node", "worker", "guard"):
        ops.checked_image(profile[name])
    for entry in preflight["evidence"]:
        if entry != profile["node"]:
            assert ops.ref(Path(entry["path"])) == entry
    root = Path(profile["run_root"])
    writable = Path(profile["properties"]["ReadWritePaths"])
    runtime_state = Path(profile["environment"]["JETSTREAMER_PRIVATE_RUN_ROOT"])
    assert preflight["writable_private_state_validated"] and writable == root / "work"
    assert runtime_state.is_relative_to(writable) and runtime_state.is_dir()
    assert runtime_state.resolve() == runtime_state
    assert profile["unit"] == scope.unit and profile["properties"]["AllowedCPUs"] == scope.cpus
    assert int(profile["properties"]["MemoryMax"]) == scope.ram
    assert profile["guarded_whole_tree_cap_bytes"] == scope.cap
    node = profile["node"]["path"]
    hook = ops.checked_image(HOOK)
    namespace = ops.bound(ops.ref(state / "namespace.json"))
    bootstrap = ops.bound(ops.ref(state / "bootstrap-recheck.json"))["bootstrap"]
    assert namespace["profile"] == scope.profile and namespace["host_guard_sees_empty_placeholders"]
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
    assert template["unit"] == scope.unit and template["worker_root"] == str(root)
    assert template["maximum_root_physical_bytes"] == scope.cap
    for directory in (root / "work/scratch", state / "guard-receipts"):
        assert not any(directory.iterdir()), directory
    for unit in (scope.unit, scope.guard, scope.guard.removesuffix(".service") + ".timer"):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    remote = inventory(kit, epoch=scope.epoch, unit=f"foundation-{scope.epoch}-focused-inventory")
    measured = current_fit(kit, roster, root, scope)
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings),
                      ReadOnlyPaths=str(tokens), Delegate="no", OOMPolicy="kill",
                      UnsetEnvironment="HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY")
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    tokens.mkdir(mode=0o755)
    tokens.chmod(0o755)
    admission = ops.funds.put(state / "admission.json", {
        "schema": f"foundation-epoch{scope.epoch}-focused-admission-v1", "epoch": scope.epoch,
        "profile": scope.profile, "preflight": scope.preflight, "roster": roster_ref, "fit": measured,
        "inventory": remote, "admitted": True, "publication_authorized": False,
    })
    owner, plan, token, active_guard = activate_guarded(
        kit, scope.epoch, state, tokens, scope.unit, scope.guard, profile["guard"], template, admission,
        props, f"ExecStartPre=/usr/bin/bash {hook} 60 {tokens}", profile["argv"])
    return ops.funds.put(state / "cadence-registration.json", {
        "schema": "jetstreamer-historical-performance-launch-receipt-v1",
        "kind": scope.kind, "epoch": scope.epoch, "unit": scope.unit,
        "run_root": str(root), "invocation_id": owner["invocation_id"], "main_pid": owner["main_pid"],
        "node_path": node, "worker": profile["worker"], "profile": scope.profile, "admission": admission,
        "guard_plan": plan, "launch_token": token, "active_guard": active_guard,
        "launched": True, "evidence": {"units": [owner]},
        "canonical_epoch_publication_authorized": False, "remote_mutations": False,
        "r2_mutations": False,
    })


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    args = sys.argv[1:]
    scope = SCOPED_ARGS[args.pop(0)] if args and args[0] in SCOPED_ARGS else LOADER_296
    roster_path, roster_sha = args
    kit = load_existing()
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    os.umask(0o077)
    remote = git("rev-parse", "origin/account-updates").decode().strip()
    for path in (Path(__file__), CONTROL / ADAPTER):
        assert path.read_bytes() == git("show", f"{remote}:{SOURCE / path.name}")
    path = Path(roster_path)
    assert path.parent.parent == V and path.name == "roster.json"
    assert path.parent.name.startswith("horizon262-foundation-roster-")
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        print(json.dumps(launch(kit, {"path": str(path), "sha256": roster_sha}, scope), indent=2))
