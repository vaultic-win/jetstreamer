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
HOURLY_230 = Scope(
    230, V / "horizon230-middle-hourly-first-runtime-v1",
    "horizon-qualify-230-middle-hourly-first-v1.service",
    "horizon-230-middle-hourly-first-protective-v1.service",
    "epoch230-private-first-hourly-window", "foundation-epoch230-hourly-first-roster-binding-v1",
    "f54a68b09830f1ae8048b4a1db29ad63f0d10cba02d34a6a06b19dbeb3f7eaab",
    "fae42b5f5183a21bed46786ddc0d23819ee1eadec8c84f9dd1a3f6debbec113b",
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
RESTORE_260 = Scope(
    260, V / "horizon260-native-restore-runtime-v1",
    "horizon-qualify-260-native-restore-v1.service",
    "horizon-260-native-restore-protective-v1.service",
    "epoch260-private-native-restore", "foundation-epoch260-native-restore-roster-binding-v1",
    "8f8b33dd3aad7a27924d22bf8c28ffa061baf0a781c68aadb8d716be50c2be23",
    "06e13588b0a57910215304785a2160dd94925a4f95dd9cbaa5951ddec153e04d",
    160 << 30, 96 << 30, 64 << 20, "56-63",
)
TRACE_296 = Scope(
    296, V / "horizon296-loader-log-v3",
    "horizon-qualify-296-loader-log-v3.service", "horizon-296-loader-log-protective-v3.service",
    "epoch296-private-loader-log-diagnostic", "foundation-epoch296-replay-roster-binding-v1",
    "a65a727024c8cc64796ce89daf0fe0ec134117a20907a8fa030526e1cfe7a073",
    "6e8be02054f2d53f51636239e2372572892dd8571f318c9af5342c2f2fe22b3f",
    173_207_977_984, 112 << 30, 64 << 20, "56-63",
)
FEATURE_296 = Scope(
    296, V / "horizon296-feature-account-v4",
    "horizon-qualify-296-feature-account-v4.service", "horizon-296-feature-account-protective-v4.service",
    "epoch296-private-feature-account-qualification", "foundation-epoch296-replay-roster-binding-v1",
    "975056b8b99b13a3d43c5b118e9f2a2ba45b2f46f1bcb9f074f0509f28d8620d",
    "76227fad5187badf638fff0220a12499f7133de851400e7b770fba712fdf05f7",
    173_207_977_984, 112 << 30, 64 << 20, "56-63",
)
SCOPED_ARGS = {
    "--epoch230": GAP_230, "--epoch258": RESTORE_258, "--epoch260": RESTORE_260,
    "--hourly230": HOURLY_230,
    "--trace296": TRACE_296, "--feature296": FEATURE_296,
}


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
    expected = set(roster["owners"])
    exposed = live - guards
    assert exposed == expected, {"unbooked": sorted(exposed - expected),
                                 "missing": sorted(expected - exposed)}
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


def prepare_hourly_retry(ops, attempt, tokens, template, guard, hook):
    def keep(path, payload):
        if path.is_file():
            reference = ops.ref(path)
            assert ops.bound(reference) == payload
            return reference
        return ops.funds.put(path, payload)

    attempt.mkdir(mode=0o700, exist_ok=True)
    receipts = attempt / "guard-receipts"
    receipts.mkdir(mode=0o700, exist_ok=True)
    for directory in (attempt, receipts):
        assert directory.resolve() == directory and directory.is_dir()
        metadata = directory.stat()
        assert metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o700
    assert not any(receipts.iterdir())
    template = dict(template, receipt_directory=str(receipts))
    static_plan = keep(attempt / "static-guard-plan.json", template)
    check = json.loads(subprocess.check_output([
        guard["path"], static_plan["path"], "--plan-sha256", static_plan["sha256"],
        "--self-sha256", guard["sha256"], "--validate-plan-only",
    ], timeout=25))
    assert check["validated"] and check["plan_sha256"] == static_plan["sha256"]
    keep(attempt / "static-guard-validation.json", check)

    probe = tokens / "qualification"
    for directory in (tokens, probe):
        if not directory.exists():
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        assert directory.resolve() == directory and directory.is_dir()
        metadata = directory.stat()
        assert metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o755
    assert set(tokens.iterdir()) == {probe}
    keep(probe / "guard-admission.json", {"qualification_only": True})
    subprocess.run(["systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                    "--unit=foundation-230-hourly-token-probe-v1",
                    "--property=User=ubuntu", "--property=Group=ubuntu",
                    "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
                    f"--property=ReadOnlyPaths={tokens}", "--property=PrivateNetwork=yes",
                    "/usr/bin/bash", "-c",
                    'INVOCATION_ID=qualification exec /usr/bin/bash "$1" 0 "$2"',
                    "token-access-probe", hook, str(tokens)], check=True, timeout=20)
    keep(attempt / "token-access-validation.json", {
        "worker_user": "ubuntu", "token_root": str(tokens), "prestart_hook": HOOK,
        "same_hook_reached_projected_token": True,
    })
    return template


def launch(kit, roster_ref, scope):
    ops = kit.ops
    state = scope.state
    attempt = state
    tokens = state / "tokens"
    failed_start = None
    if scope is HOURLY_230:
        failed_start = {
            "path": str(state / "prestart-failure-881df10b.json"),
            "sha256": "958af848bc8663315dfe94ca2945b99415cee39da47ff017ba3f4b0e8c4eb036",
        }
        failure = ops.bound(failed_start)
        assert failure["epoch"] == scope.epoch and failure["worker_started"] is False
        assert failure["timer_after"]["ActiveState"] == "inactive"
        assert failure["producer"]["ExecMainStartTimestampMonotonic"] == "0"
        assert failure["guard_token_exists"] and failure["prestart_uid_can_reach_token"] is False
        attempt = state / "retry-v1"
        tokens = V / "horizon230-middle-hourly-first-tokens-retry-v1"
    assert not (state / "cadence-registration.json").exists()
    assert not (attempt / "admission.json").exists()
    assert failed_start is not None or not tokens.exists()
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
    assert not any((root / "work/scratch").iterdir())
    if failed_start is None:
        assert not any((state / "guard-receipts").iterdir())
    for unit in (scope.unit, scope.guard, scope.guard.removesuffix(".service") + ".timer"):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    remote = inventory(kit, epoch=scope.epoch, unit=f"foundation-{scope.epoch}-focused-inventory")
    if failed_start is not None:
        template = prepare_hourly_retry(ops, attempt, tokens, template, profile["guard"], hook)
    measured = current_fit(kit, roster, root, scope)
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings),
                      ReadOnlyPaths=str(tokens), Delegate="no", OOMPolicy="kill",
                      UnsetEnvironment="HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY")
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    if failed_start is None:
        tokens.mkdir(mode=0o755)
        tokens.chmod(0o755)
    admission = ops.funds.put(attempt / "admission.json", {
        "schema": f"foundation-epoch{scope.epoch}-focused-admission-v1", "epoch": scope.epoch,
        "profile": scope.profile, "preflight": scope.preflight, "roster": roster_ref, "fit": measured,
        "inventory": remote, "admitted": True, "publication_authorized": False,
        **({"failed_prestart": failed_start} if failed_start is not None else {}),
    })
    owner, plan, token, active_guard = activate_guarded(
        kit, scope.epoch, attempt, tokens, scope.unit, scope.guard, profile["guard"], template, admission,
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
