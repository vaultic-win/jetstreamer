"""Admit a private checkpoint-bounded replay using the sealed guard."""

import fcntl
import json
import os
import stat
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
import epoch266_overlap


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
        if self.kind == "epoch266-private-original-predecessor":
            return {"path": str(V / "horizon266-original-predecessor-static-v1/profile.json"),
                    "sha256": self.profile_sha}
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
SECOND_HOURLY_230 = Scope(
    230, V / "horizon230-middle-hourly-second-runtime-v1",
    "horizon-qualify-230-middle-hourly-second-v1.service",
    "horizon-230-middle-hourly-second-protective-v1.service",
    "epoch230-private-second-hourly-window", "foundation-epoch230-hourly-second-roster-binding-v1",
    "76787b9a49ef39f2ae2e7cb6053abdc4e1d075301527e72b1878f9165c9cfe38",
    "b7d2b77d99c3d42d6e85b9b724876ba700f6c598df75ade8bcc7db945907edda",
    225_000_000_000, 208 << 30, 256 << 20, "48-55",
)
FIRST_7871_230 = Scope(
    230, V / "horizon230-first-7871-runtime-v1",
    "horizon-qualify-230-first-7871-v1.service", "horizon-230-first-7871-protective-v1.service",
    "epoch230-private-first-7871-window", "foundation-epoch230-first-7871-roster-binding-v1",
    "7d3a7c8bad8d3b257622800874a92a278d287a6b1cd6d377f729c2e139e9f4fd",
    "3c0d5ac1c970cffa0473fa3c5d01ad2466f7d041b4fe25dc7cdb65039688a3ea",
    225_000_000_000, 90 << 30, 256 << 20, "48-55",
)
V1627_230 = Scope(
    230, V / "horizon230-v1627-replay-runtime-v1",
    "horizon-qualify-230-v1627-window-v1.service", "horizon-230-v1627-window-protective-v1.service",
    "epoch230-private-v1627-window", "foundation-epoch230-v1627-window-roster-binding-v1",
    "1e300ad51ba5f75a91af2f68c80241dd90a5c6d279b630de8f92f882655b43d5",
    "8301ba667e1f440365cc40dcdbe4b5f69fa6d224e2e754734738908345b35cca",
    225_000_000_000, 90 << 30, 256 << 20, "48-55",
)
ADJACENT_230 = Scope(
    230, V / "horizon230-adjacent-99445304-runtime-v1",
    "horizon-qualify-230-adjacent-99445304-v1.service", "horizon-230-adjacent-99445304-protective-v1.service",
    "epoch230-private-adjacent-99445304-window", "foundation-epoch230-adjacent-replay-roster-binding-v1",
    "d01cf1c1a583c41e885ea74f57aea21a5e5178554e94bca16d01674a5bff1d1b",
    "e2482b9f1a94143620adae00bc4aef749b7004fa32fd2e7671643d62f7d9470a",
    225_000_000_000, 96 << 30, 256 << 20, "48-55",
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
OVERLAP_266 = Scope(
    266, epoch266_overlap.STATE, epoch266_overlap.UNIT, epoch266_overlap.GUARD_UNIT,
    "epoch266-private-hourly-overlap", "foundation-epoch266-hourly-overlap-roster-binding-v1",
    "494849a05eb8b63f1770c5ae54dc63a1cc1dfadbd09b235c3938ee28393d08ea",
    "1e014dac29ed075242cccd2d226c75a3088712540a90a7358b1cecee4df04b65",
    epoch266_overlap.PRODUCER_RAM, epoch266_overlap.HOME, epoch266_overlap.RECEIPTS, epoch266_overlap.CPU,
)
PREDECESSOR_266 = Scope(
    266, V / "horizon266-original-predecessor-runtime-v1",
    "horizon-qualify-266-original-predecessor-v1.service",
    "horizon-266-original-predecessor-protective-v1.service",
    "epoch266-private-original-predecessor", "foundation-epoch266-original-predecessor-roster-binding-v1",
    "7ed80c05ae0e1c706a271452d9b0dcb516c651fd0f97a2ec3f1c61a477a30f21",
    "de5680f4fc6634529348c9701f639a66cf333c7296f69a7645dc97f1297bc4ae",
    epoch266_overlap.PRODUCER_RAM, epoch266_overlap.HOME, epoch266_overlap.RECEIPTS, epoch266_overlap.CPU,
)
PREDECESSOR_CUSTODY = {
    "path": str(V / "horizon266-predecessor-intake-stage-v1/custody.json"),
    "sha256": "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959",
}
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
    "--hourly230": HOURLY_230, "--hourly230-second": SECOND_HOURLY_230,
    "--overlap266": OVERLAP_266,
    "--predecessor266": PREDECESSOR_266,
    "--adjacent230": ADJACENT_230,
    "--first7871-230": FIRST_7871_230, "--v1627-230": V1627_230, "--trace296": TRACE_296, "--feature296": FEATURE_296,
}


def protected_226_fit(fit):
    status = fit["protected_226_suffix_state"]
    assert status in ("pending", "live", "verified-closed")
    expected = ((160 << 30) + (256 << 20), (161 << 30) + (256 << 20)) if status == "pending" else (0, 0)
    assert (fit["pending_suffix226_disk_bytes"], fit["pending_suffix226_memory_bytes"]) == expected


def second_hourly_drained(ops, terminal_ref):
    require_230_drained(ops, terminal_ref, SECOND_HOURLY_230, {
        "path": str(SECOND_HOURLY_230.state / "terminal.json"),
        "sha256": "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56",
    }, "a0a94d2d42984804877c1a80fc934585", 99_516_304)


def require_230_drained(ops, terminal_ref, scope, expected, invocation, checkpoint):
    assert terminal_ref == expected
    terminal = ops.bound(terminal_ref)
    assert terminal["unit"] == scope.unit and terminal["guard_drained"]
    assert terminal["invocation_id"] == invocation
    assert terminal["state"] == "local-segment-committed" and terminal["checkpoint"]["slot"] == checkpoint
    assert ops.props(scope.guard.removesuffix(".service") + ".timer", ["ActiveState", "Job"]) == {
        "ActiveState": "inactive", "Job": ""}
    for unit in (scope.unit, scope.guard):
        owner = ops.props(unit, ["ActiveState", "Result", "InvocationID", "Job", "MainPID", "ControlPID", "ControlGroup"])
        assert owner["ActiveState"] in ("inactive", "failed") and not owner["Job"] and not owner["ControlGroup"]
        assert owner["MainPID"] == owner["ControlPID"] == "0"
        assert not (Path("/sys/fs/cgroup/system.slice") / unit).exists()
        if unit == scope.unit:
            assert owner["Result"] == "success" and owner["InvocationID"] in ("", terminal["invocation_id"])


def current_fit(kit, roster, root, scope, *, held=False):
    ops = kit.ops
    fit = roster["capacity"]
    assert roster["schema"] == scope.roster_schema
    assert not roster["admission_issued"] and not roster["candidate_held"]
    assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 90
    assert roster[f"focused_{scope.epoch}_quote"]["preflight"] == scope.preflight and fit["fits"]
    assert fit["candidate_disk_bytes"] == scope.cap + scope.receipts
    control_ram = epoch266_overlap.CONTROL_RAM if scope.epoch == 266 else (256 << 20)
    assert fit["candidate_total_memory_bytes"] == scope.ram + (1 << 30) + control_ram
    if scope.epoch == 266:
        suffix = fit["protected_226_suffix_state"]
        protected_226_fit(fit)
        assert (roster["active_suffix_226_registration"] is not None) == (suffix == "live")
    assert fit["guard_floor_bytes"] == 3_770_104_987_645
    cpus = kit.measure.source.helper.cpus
    selected = cpus(scope.cpus)
    assert cpus(fit["cpus"]) == selected
    protected_cpus = selected
    if scope in (SECOND_HOURLY_230, FIRST_7871_230, V1627_230, ADJACENT_230):
        protected_cpus = set().union(*(cpus(Path(
            f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ).read_text().replace(",", " ")) for cpu in selected))
        assert selected <= protected_cpus
    if scope in (FIRST_7871_230, V1627_230, ADJACENT_230):
        proof = roster["focused_230_quote"]
        assert sorted(protected_cpus) == proof["exclusive_online_cpus"] == [*range(48, 56), *range(112, 120)]
        protected_226_fit(fit)
        if scope is FIRST_7871_230:
            second_hourly_drained(ops, proof["predecessor_terminal"])
        else:
            require_230_drained(ops, proof["predecessor_terminal"], FIRST_7871_230, {
                "path": str(FIRST_7871_230.state / "terminal.json"),
                "sha256": "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2",
            }, "02b7dd1683d24efbabf6b5c2f8ff6a43", 99_445_304)
    if scope.epoch == 266:
        protected_cpus = epoch266_overlap.EXCLUSIVE
        assert roster["focused_266_quote"]["exclusive_online_cpus"] == sorted(protected_cpus)
        for cpu in (*selected, 30):
            sibling_path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
            assert cpus(sibling_path.read_text().replace(",", " ")) == {cpu, cpu + 64}
        assert protected_cpus.isdisjoint(cpus("16-23 80-87"))
    if scope is PREDECESSOR_266:
        assert roster["focused_266_quote"]["bootstrap_custody"] == PREDECESSOR_CUSTODY
    listing = subprocess.check_output(
        ["systemctl", "list-units", "--type=service", "--state=running,activating",
         "--plain", "--no-legend", "--no-pager"], text=True, timeout=10)
    live = {line.split()[0] for line in listing.splitlines()
            if line.startswith(("horizon-", "foundation-", "archive-", "jetstreamer-"))}
    guards = {row["unit"] for row in roster["periodic_guards"].values()}
    expected = set(roster["owners"])
    if held:
        assert scope.epoch == 266 and scope.unit in live
        guards.update((scope.unit, scope.guard))
    exposed = live - guards
    assert exposed == expected, {"unbooked": sorted(exposed - expected),
                                 "missing": sorted(expected - exposed)}
    growth = fit["required_remaining_memory_bytes"]
    for unit, row in roster["owners"].items():
        current = ops.props(unit, [*FIELDS, "MemoryCurrent"])
        assert all(current[key] == row["systemd"][key] for key in FIELDS)
        assert protected_cpus.isdisjoint(cpus(current["AllowedCPUs"]))
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
            "required_remaining_memory_bytes": growth, "sampled_unix_seconds": time.time(),
            **({"protected_cpus": sorted(protected_cpus)} if scope in
               (SECOND_HOURLY_230, FIRST_7871_230, V1627_230, ADJACENT_230, OVERLAP_266, PREDECESSOR_266) else {})}


def prepare_hourly_tokens(ops, attempt, tokens, template, guard, hook, probe_unit):
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
                    f"--unit={probe_unit}",
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


def predecessor_namespace(ops, scope, preflight, profile):
    custody = ops.bound(PREDECESSOR_CUSTODY)
    proof = ops.bound(custody["namespace"])
    guard = ops.bound(preflight["static_guard_validation"])
    assert preflight["profile"] == custody["profile"] == scope.profile
    assert (preflight["replay_first_slot"], preflight["output_first_slot"], preflight["last_slot"]) == (
        114_910_769, 114_912_000, 114_923_430)
    assert custody["whole_file_sha256_rechecked"] and custody["actual_readonly_projection_verified"]
    assert not (custody["replay_launch_authorized"] or custody["publication_authorized"])
    assert guard["validated"] and guard["plan_sha256"] == profile["static_guard_plan"]["sha256"]
    assert proof["readonly_binds"] and proof["host_backed_output"]
    assert proof["unprivileged_token_hook_reached"] and not proof["worker_executed"]
    assert proof["scratch_noswap"] and proof["scratch_tmpfs_bytes"] == 128 << 30
    input_proof = custody["input"]
    for field in ("path", "bytes", "generation", "sha256"):
        assert input_proof[field] == profile["bootstrap"][field]
    assert input_proof["root_sealed"] and input_proof["identity"] == proof["source_identities"][-1]
    mounted = []
    for row, identity in zip(profile["readonly_bindings"], proof["source_identities"], strict=True):
        source = Path(row["path"])
        info = source.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o222 == 0
        assert info.st_nlink == 1 and source.resolve() == source
        assert identity == {
            "device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
            "mtime": list(divmod(info.st_mtime_ns, 10**9)),
            "ctime": list(divmod(info.st_ctime_ns, 10**9)),
        }
        mounted.append(f"{info.st_dev}:{info.st_ino}:{info.st_size}")
    assert profile["properties"]["BindReadOnlyPaths"] == " ".join(
        f'{row["path"]}:{row["destination"]}' for row in profile["readonly_bindings"])
    info = Path(input_proof["path"]).stat()
    return {"mounted_device_inode_size": mounted}, {
        "path": input_proof["path"],
        "identity": f"{info.st_dev}:{info.st_ino}:{info.st_size}:{int(info.st_mtime)}:{int(info.st_ctime)}",
    }


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
    if scope is SECOND_HOURLY_230:
        tokens = V / "horizon230-middle-hourly-second-tokens-v1"
    if scope is FIRST_7871_230:
        tokens = V / "horizon230-first-7871-tokens-v1"
    if scope is V1627_230:
        tokens = V / "horizon230-v1627-tokens-v1"
    if scope is ADJACENT_230:
        tokens = V / "horizon230-adjacent-99445304-tokens-v1"
    assert not (state / "cadence-registration.json").exists()
    assert not (attempt / "admission.json").exists()
    if scope is OVERLAP_266:
        tokens = epoch266_overlap.TOKENS
    if scope is PREDECESSOR_266:
        tokens = V / "horizon266-original-predecessor-tokens-v1"
    qualify_tokens = failed_start is not None or scope in (SECOND_HOURLY_230, FIRST_7871_230, V1627_230, ADJACENT_230,
                                                           OVERLAP_266, PREDECESSOR_266)
    assert qualify_tokens or not tokens.exists()
    roster = ops.bound(roster_ref)
    preflight = ops.bound(scope.preflight)
    profile = ops.bound(scope.profile)
    images = [profile[name] for name in ("node", "worker", "guard")]
    for image in images:
        ops.checked_image(image)
    for entry in preflight.get("evidence", ()):
        if entry not in images:
            assert ops.ref(Path(entry["path"])) == entry
    root = Path(profile["run_root"])
    writable = Path(profile["properties"]["ReadWritePaths"])
    runtime_state = Path(profile["environment"]["JETSTREAMER_PRIVATE_RUN_ROOT"])
    assert writable == root / "work"
    assert runtime_state.is_relative_to(writable) and runtime_state.is_dir()
    assert runtime_state.resolve() == runtime_state
    assert profile["unit"] == scope.unit and profile["properties"]["AllowedCPUs"] == scope.cpus
    assert int(profile["properties"]["MemoryMax"]) == scope.ram
    assert profile["guarded_whole_tree_cap_bytes"] == scope.cap
    if scope is OVERLAP_266:
        epoch266_overlap.validate_sources()
        assert profile == json.loads(epoch266_overlap.files()["profile.json"])
    node = profile["node"]["path"]
    hook = ops.checked_image(HOOK)
    if scope is PREDECESSOR_266:
        namespace, bootstrap = predecessor_namespace(ops, scope, preflight, profile)
    else:
        namespace = ops.bound(ops.ref(state / "namespace.json"))
        bootstrap = ops.bound(ops.ref(state / "bootstrap-recheck.json"))["bootstrap"]
        if scope is ADJACENT_230:
            assert preflight["profile"] == scope.profile
            assert namespace["mounted_device_inode_size"] == preflight["readonly_mounted_device_inode_size"]
            assert preflight["host_guard_sees_empty_placeholders"] and not preflight["worker_execution"]
            assert preflight["bootstrap_custody"] == profile["bootstrap_custody"]
            custody = ops.bound(profile["bootstrap_custody"])
            assert all(bootstrap[key] == custody["snapshot"][key] for key in ("path", "sha256"))
            assert ops.ref(Path(profile["epoch_hashes"]["path"])) == profile["epoch_hashes"]
            assert ops.bound(preflight["guard_validation"])["plan_sha256"] == profile["static_guard_plan"]["sha256"]
        else:
            assert preflight["writable_private_state_validated"]
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
        if scope in (FIRST_7871_230, V1627_230, ADJACENT_230):
            assert (info.st_mtime_ns, info.st_ctime_ns) == (binding["mtime_ns"], binding["ctime_ns"])
            assert info.st_nlink == 1 and not source.is_symlink()
        bindings.append(f"{source}:{destination}")
    snapshot = Path(bootstrap["path"]).stat()
    assert bootstrap["identity"] == (
        f"{snapshot.st_dev}:{snapshot.st_ino}:{snapshot.st_size}:"
        f"{int(snapshot.st_mtime)}:{int(snapshot.st_ctime)}")
    template = ops.bound(profile["static_guard_plan"])
    if scope is OVERLAP_266:
        assert bootstrap["sha256"] == epoch266_overlap.SNAPSHOT["sha256"]
        assert snapshot.st_mtime_ns == bootstrap["mtime_ns"] and snapshot.st_ctime_ns == bootstrap["ctime_ns"]
        assert namespace["tmpfs_private_to_producer_and_noswap"] and namespace["persistent_output_on_home"]
        assert [list(epoch266_overlap.stable_identity(Path(row["path"])))
                for row in profile["readonly_bindings"]] == namespace["source_identities"]
    assert template["unit"] == scope.unit and template["worker_root"] == str(root)
    assert template["maximum_root_physical_bytes"] == scope.cap
    scratch = root / "work/scratch"
    if scope is SECOND_HOURLY_230:
        cli_scratch = scratch / ".historical-runtime"
        assert set(scratch.iterdir()) <= {cli_scratch}
        if cli_scratch.exists():
            assert cli_scratch.resolve() == cli_scratch and not any(cli_scratch.iterdir())
    else:
        assert not any(scratch.iterdir())
    if failed_start is None:
        assert not any((state / "guard-receipts").iterdir())
    for unit in (scope.unit, scope.guard, scope.guard.removesuffix(".service") + ".timer"):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    remote = inventory(kit, epoch=scope.epoch, unit=f"foundation-{scope.epoch}-focused-inventory")
    if qualify_tokens:
        probe_unit = ("foundation-230-hourly-second-token-probe-v1" if scope is SECOND_HOURLY_230
                      else "foundation-230-hourly-token-probe-v1")
        if scope is FIRST_7871_230:
            probe_unit = "foundation-230-first-7871-token-probe-v1"
        elif scope is V1627_230:
            probe_unit = "foundation-230-v1627-token-probe-v1"
        elif scope is ADJACENT_230:
            probe_unit = "foundation-230-adjacent-99445304-token-probe-v1"
        elif scope is OVERLAP_266:
            probe_unit = "foundation-266-overlap-token-probe-v1"
        elif scope is PREDECESSOR_266:
            probe_unit = "foundation-266-predecessor-token-probe-v1"
        template = prepare_hourly_tokens(ops, attempt, tokens, template, profile["guard"], hook, probe_unit)
    measured = current_fit(kit, roster, root, scope)
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings),
                      ReadOnlyPaths=str(tokens), Delegate="no", OOMPolicy="kill",
                      UnsetEnvironment="HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY")
    if scope.epoch == 266:
        properties["UnsetEnvironment"] += " HORIZON_PUBLIC_BASE_URL"
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    if not qualify_tokens:
        tokens.mkdir(mode=0o755)
        tokens.chmod(0o755)
    admission = ops.funds.put(attempt / "admission.json", {
        "schema": f"foundation-epoch{scope.epoch}-focused-admission-v1", "epoch": scope.epoch,
        "profile": scope.profile, "preflight": scope.preflight, "roster": roster_ref, "fit": measured,
        "inventory": remote, "admitted": True, "publication_authorized": False,
        **({"failed_prestart": failed_start} if failed_start is not None else {}),
    })
    def before_266_release(held, guard_plan, sample, clock, next_tick):
        assert sample["producer_invocation_id"] == held["InvocationID"]
        assert sample["plan_sha256"] == guard_plan["sha256"] and sample["trip_reason"] is None
        assert clock["ActiveState"] == "active" and next_tick > time.monotonic_ns() // 1000
        assert ops.props(scope.guard, ["AllowedCPUs", "MemoryMax"]) == {
            "AllowedCPUs": "30", "MemoryMax": str(epoch266_overlap.GUARD_RAM)}
        confirmation = current_fit(kit, roster, root, scope, held=True)
        ops.funds.put(attempt / "guard-release-fit.json", {
            "schema": ("foundation-epoch266-original-predecessor-guard-release-fit-v1"
                       if scope is PREDECESSOR_266 else "foundation-epoch266-hourly-overlap-guard-release-fit-v1"),
            "invocation_id": held["InvocationID"], "roster": roster_ref, "guard_plan": guard_plan,
            "fit": confirmation, "publication_authorized": False,
        })

    owner, plan, token, active_guard = activate_guarded(
        kit, scope.epoch, attempt, tokens, scope.unit, scope.guard, profile["guard"], template, admission,
        props, f"ExecStartPre=/usr/bin/bash {hook} 60 {tokens}", profile["argv"],
        **({"guard_cpuset": "30", "before_release": before_266_release} if scope.epoch == 266 else {}))
    return ops.funds.put(state / "cadence-registration.json", {
        "schema": "jetstreamer-historical-performance-launch-receipt-v1",
        "kind": scope.kind, "epoch": scope.epoch, "unit": scope.unit,
        "run_root": str(root), "invocation_id": owner["invocation_id"], "main_pid": owner["main_pid"],
        "node_path": node, "worker": profile["worker"], "profile": scope.profile, "admission": admission,
        "guard_plan": plan, "launch_token": token, "active_guard": active_guard,
        "launched": True, "evidence": {"units": [owner]},
        "canonical_epoch_publication_authorized": False, "remote_mutations": False,
        "r2_mutations": False,
        **({"diagnostic_only": True,
            "predecessor_native_tuple_qualified": False, "cursor_normalization_qualified": False,
            **({"bootstrap_custody": PREDECESSOR_CUSTODY} if scope is PREDECESSOR_266
               else {"lossless_restore": epoch266_overlap.RESTORE}),
            "guard_release_fit": ops.ref(attempt / "guard-release-fit.json")}
           if scope.epoch == 266 else {}),
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
    scripts = [Path(__file__), CONTROL / ADAPTER]
    if scope.epoch == 266:
        scripts.extend((Path(epoch266_overlap.__file__), Path(activate_guarded.__code__.co_filename)))
    for path in scripts:
        assert path.read_bytes() == git("show", f"{remote}:{SOURCE / path.name}")
    path = Path(roster_path)
    assert path.parent.parent == V and path.name == "roster.json"
    assert path.parent.name.startswith("horizon262-foundation-roster-")
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        print(json.dumps(launch(kit, {"path": str(path), "sha256": roster_sha}, scope), indent=2))
