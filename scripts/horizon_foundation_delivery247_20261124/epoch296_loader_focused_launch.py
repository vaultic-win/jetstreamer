"""Admit a private checkpoint-bounded replay using the sealed guard."""

import fcntl
import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
import subprocess
import sys
import tempfile
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
SUCCESSOR_REPLAY_230 = replace(
    FIRST_7871_230,
    state=V / "horizon230-successor-99516304-runtime-v1",
    unit="horizon-qualify-230-successor-99516304-v1.service",
    guard="horizon-230-successor-99516304-protective-v1.service",
    kind="epoch230-private-successor-99516304-window",
    roster_schema="foundation-epoch230-successor-replay-roster-binding-v1",
    profile_sha="5a3fbf5e9cc3289a374a2cf54b6b78f3dfa859bb92d54b75625ea1f3daa204a2",
    preflight_sha="a91b6d9623091e5e4e830f9889fc3d4d4f814947b804d5e01d5070845c594d0e",
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
NEXT_V1627_230 = Scope(
    230, V / "horizon230-next-v1627-window-runtime-v1",
    "horizon-qualify-230-next-v1627-99468089-v1.service",
    "horizon-230-next-v1627-99468089-protective-v1.service",
    "epoch230-private-next-v1627-window", "foundation-epoch230-next-v1627-roster-binding-v1",
    "f289cdf8e6c6d85f387a2deac22c2c7ef19fcb1b4b98bc75230162a2cbf71447",
    "c54b1b9fc120a920e23d220b3d223565b7e0a5cd92f6206103c426b545431c48",
    225_000_000_000, 96 << 30, 256 << 20, "48-55",
)
RETRY_NEXT_V1627_230 = replace(
    NEXT_V1627_230, state=V / "horizon230-next-v1627-retry-runtime-v2",
    unit="horizon-qualify-230-next-v1627-99468089-v2.service",
    guard="horizon-230-next-v1627-99468089-protective-v2.service",
    kind="epoch230-private-next-v1627-worker-retry", roster_schema="foundation-epoch230-next-v1627-retry-roster-binding-v2",
    profile_sha="eaaff300d82fe6576331b49876b910e5f296efb61e19a5239505554ac209c95e",
    preflight_sha="c091acc448841a3051c5954347f478d749d1c9766ce0f8dfca88bea39cbe1cd9",
)
NEXT_V1627_SCOPES = (NEXT_V1627_230, RETRY_NEXT_V1627_230)
BRIDGE_230 = (FIRST_7871_230, SUCCESSOR_REPLAY_230, V1627_230, ADJACENT_230, *NEXT_V1627_SCOPES)
NEXT_V1627_230_FLEET = V / "horizon230-next-v1627-fleet-v1/acceptance.json"
RETRY_NEXT_V1627_230_FLEET = V / "horizon230-next-v1627-retry-fleet-v2/acceptance.json"
NEXT_V1627_FAILED_START = {
    "path": str(NEXT_V1627_230.state / "terminal.json"),
    "sha256": "a97fc5e092e642ac61b3fca84e983d8b70c49a635392b60e3549e99c34f98852",
}
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
WINDOW_266 = Scope(
    266, V / "horizon266-window-114929698-114936474-runtime-v1",
    "horizon-qualify-checkpoint-continuation-266-window-114936474-v1.service",
    "horizon-266-window-114936474-protective-v1.service",
    "epoch266-private-hourly-window", "foundation-epoch266-private-window-roster-binding-v1",
    "f7562054a31277bc38747652f9a79e6967b393d8713499e6998841390cb4c5d6",
    "9043e168fd2322c6c5e098bee42a40f69507fa9db7afd791ad59577354f3bed1",
    epoch266_overlap.PRODUCER_RAM, epoch266_overlap.HOME, epoch266_overlap.RECEIPTS, epoch266_overlap.CPU,
)
WINDOW_266_TOKEN_PROBE = {
    "path": str(WINDOW_266.state / "evidence/prestart-token-probe.json"),
    "sha256": "6a6bcfc6d9e317fd73c9e7b6b6b4222726ba3cb9db7d2439c1b65b498cb0f57f",
}
WINDOW_266_FLEET = V / "horizon266-window-fleet-v1/acceptance.json"
WINDOW_266_PLAN = V / "horizon266-window-admitted-v1"
SUCCESSOR_266 = replace(
    WINDOW_266,
    state=V / "horizon266-window-114936475-114943135-runtime-v1",
    unit="horizon-qualify-checkpoint-continuation-266-window-114943135-v1.service",
    guard="horizon-266-window-114943135-protective-v1.service",
    profile_sha="eacf3e685a72ad196734b20d7a8a00924176cb6e324aea6ce52f55a983e1fc30",
    preflight_sha="90a972850c9dd75ec6939a081f5b117513e563db3813a7b3e7e115c15ad8d476",
)
SUCCESSOR_266_TOKEN_PROBE = {
    "path": str(SUCCESSOR_266.state / "evidence/prestart-token-probe.json"),
    "sha256": "3ce24c5c17f48bd351110cb727bfcc15d1be5c5f457e26f6196777fc93a93db2",
}
SUCCESSOR_266_FLEET = V / "horizon266-successor-window-fleet-v1/acceptance.json"
SUCCESSOR_266_PLAN = V / "horizon266-successor-window-admitted-v1"
FOLLOWING_266 = replace(
    WINDOW_266,
    state=V / "horizon266-window-114943136-114949777-runtime-v1",
    unit="horizon-qualify-checkpoint-continuation-266-window-114949777-v1.service",
    guard="horizon-266-window-114949777-protective-v1.service",
    profile_sha="4709cbc3baf7d27acc46e2ea6d2aec7a658bf4ecc23a70f0f571c27ba61068f6",
    preflight_sha="4b830983a43c0a90eeb1ade4c90664940d2b56152b93c73fd09df2582d28c700",
)
FOLLOWING_266_TOKEN_PROBE = {
    "path": str(FOLLOWING_266.state / "evidence/prestart-token-probe.json"),
    "sha256": "3e88db7fbf8a97afe25940fc4bce205a76012a03cc12e82886b30b898dc06b31",
}
FOLLOWING_266_FLEET = V / "horizon266-following-window-fleet-v1/acceptance.json"
FOLLOWING_266_PLAN = V / "horizon266-following-window-admitted-v1"
FOLLOWING_266_DRAIN = {
    "path": str(SUCCESSOR_266.state / "terminal.json"),
    "sha256": "939d32b372e8052de5f8b154720e0600de837d5f02c79334cf5e5d4e0af868b1",
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
    "--window266": WINDOW_266,
    "--successor266": SUCCESSOR_266,
    "--following266": FOLLOWING_266,
    "--epoch230": GAP_230, "--epoch258": RESTORE_258, "--epoch260": RESTORE_260,
    "--hourly230": HOURLY_230, "--hourly230-second": SECOND_HOURLY_230,
    "--overlap266": OVERLAP_266,
    "--predecessor266": PREDECESSOR_266,
    "--adjacent230": ADJACENT_230,
    "--next-v1627-230": NEXT_V1627_230,
    "--retry-next-v1627-230": RETRY_NEXT_V1627_230,
    "--successor-replay-230": SUCCESSOR_REPLAY_230,
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
    checkpoint_record = (ops.bound(terminal["native_terminal"])["terminal_checkpoint"]
                         if scope is V1627_230 else terminal["checkpoint"])
    assert terminal["state"] == "local-segment-committed" and checkpoint_record["slot"] == checkpoint
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
    if scope in (SECOND_HOURLY_230, *BRIDGE_230):
        protected_cpus = set().union(*(cpus(Path(
            f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ).read_text().replace(",", " ")) for cpu in selected))
        assert selected <= protected_cpus
    if scope in BRIDGE_230:
        proof = roster["focused_230_quote"]
        assert sorted(protected_cpus) == proof["exclusive_online_cpus"] == [*range(48, 56), *range(112, 120)]
        protected_226_fit(fit)
        if scope in (FIRST_7871_230, SUCCESSOR_REPLAY_230):
            second_hourly_drained(ops, proof["predecessor_terminal"])
        elif scope in NEXT_V1627_SCOPES:
            require_230_drained(ops, proof["predecessor_terminal"], V1627_230, {
                "path": str(V1627_230.state / "terminal.json"),
                "sha256": "db618cf906b39ffe64f80b7a0c90febaa4d54054cac4a74e2fed12cea772846e",
            }, "6c878d138821422d8a848d6bd16d63a9", 99_468_089)
            if scope is RETRY_NEXT_V1627_230:
                assert proof["failed_predecessor_terminal"] == NEXT_V1627_FAILED_START
                failed = ops.bound(NEXT_V1627_FAILED_START)
                assert failed["state"] == "worker-startup-rejected" and failed["guard_drained"]
                assert failed["invocation_id"] == "f6cc2515791d43f9991ef0247dbc3e9d"
                prior_timer = NEXT_V1627_230.guard.removesuffix(".service") + ".timer"
                assert ops.props(prior_timer, ["ActiveState", "Job"]) == {"ActiveState": "inactive", "Job": ""}
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
               (SECOND_HOURLY_230, *BRIDGE_230, OVERLAP_266, PREDECESSOR_266) else {})}


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


def launch_window_266(kit, roster_ref, scope):
    """Use the existing invocation-bound startup for the sealed continuation."""
    ops = kit.ops
    if scope is FOLLOWING_266:
        fleet = FOLLOWING_266_FLEET
        plan_path = FOLLOWING_266_PLAN
        token_probe = FOLLOWING_266_TOKEN_PROBE
        release_schema = "foundation-epoch266-following-window-fleet-release-v1"
    elif scope is SUCCESSOR_266:
        fleet = SUCCESSOR_266_FLEET
        plan_path = SUCCESSOR_266_PLAN
        token_probe = SUCCESSOR_266_TOKEN_PROBE
        release_schema = "foundation-epoch266-successor-window-fleet-release-v1"
    else:
        fleet = WINDOW_266_FLEET
        plan_path = WINDOW_266_PLAN
        token_probe = WINDOW_266_TOKEN_PROBE
        release_schema = "foundation-epoch266-window-fleet-release-v1"
    state = scope.state
    roster = ops.bound(roster_ref)
    profile = ops.bound(scope.profile)
    root = Path(profile["run_root"])
    current_fit(kit, roster, root, scope)
    assert not (state / "cadence-registration.json").exists() and not plan_path.exists()
    acceptance = ops.bound(ops.ref(fleet))
    assert acceptance["schema"] == release_schema
    assert acceptance["preflight"] == scope.preflight and acceptance["fleet_reconcile_only"]
    assert acceptance["admission_authorized"] is False and acceptance["publication_authorized"] is False
    ops.checked_image(acceptance["fleet"])
    for name in ("adapter", "cycle"):
        saved = acceptance[name]
        filename = ADAPTER if name == "adapter" else "cycle.py"
        assert ops.ref(Path(saved["path"])) == saved
        assert (CONTROL / filename).read_bytes() == Path(saved["path"]).read_bytes()
    for name in ("node", "worker", "guard"):
        ops.checked_image(profile[name])
    hook = ops.checked_image(HOOK)
    preflight = ops.bound(scope.preflight)
    mount = ops.bound(preflight["mount_preflight"])
    assert preflight["profile"] == scope.profile and preflight["worker_execution"] is False
    assert mount["all_input_mounts_readonly"] and mount["scratch_noswap"]
    custody = profile["bootstrap_custody"]
    ops.bound(custody)
    assert roster["focused_266_quote"]["bootstrap_custody"] == custody
    tokens = state / "tokens"
    probe = ops.bound(token_probe)
    assert probe["token_root"] == str(tokens) and probe["prestart_hook"] == HOOK
    assert probe["qualification_only"] and probe["same_hook_reached_projected_token"]
    if scope in (SUCCESSOR_266, FOLLOWING_266):
        assert probe["missing_token_rejected"] and probe["stale_token_rejected"]
    assert set(tokens.iterdir()) == {tokens / "qualification"}
    assert not any((state / "guard-receipts").iterdir())
    views = mount["snapshot_and_index_views"]
    bindings = []
    for view, expected in zip(profile["readonly_bindings"], views, strict=True):
        source, target = Path(view["path"]), Path(view["target"])
        info = source.lstat()
        assert all(view[key] == expected[key] for key in ("path", "target", "sha256"))
        assert source.resolve() == source and target.resolve() == target
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and not info.st_mode & 0o222
        assert (info.st_dev, info.st_ino, info.st_size) == tuple(expected[key] for key in ("device", "inode", "bytes"))
        assert target.lstat().st_size == 0
        bindings.append(f"{source}:{target}")
    projection = None
    if scope is FOLLOWING_266:
        assert roster["focused_266_quote"]["predecessor_drain"] == FOLLOWING_266_DRAIN
        drained = ops.bound(FOLLOWING_266_DRAIN)
        assert drained["unit"] == SUCCESSOR_266.unit and drained["guard_drained"]
        assert drained["state"] == "local-segment-committed"
        projection = profile["bootstrap_custody_projection"]
        assert mount["custody_mount"] == dict(projection, readonly=True, exact_bytes=True)
        assert projection["host_custody"] == custody
        assert projection["source_custody"]["sha256"] == custody["sha256"]
        assert Path(custody["path"]).parent == Path(projection["target"])
        read_only_custody = Path(projection["source"]) / "custody.json"
        assert ops.ref(read_only_custody) == projection["source_custody"]
        assert read_only_custody.stat().st_uid == 0 and not read_only_custody.stat().st_mode & 0o222
        bindings.append("{source}:{target}".format(**projection))
    for unit in (scope.unit, scope.guard, scope.guard.removesuffix(".service") + ".timer"):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    assert not any((root / "scratch").iterdir())
    assert {p.name for p in (root / "ledger").iterdir()} == {"compact-indexes"}
    inventory_unit = {
        FOLLOWING_266.unit: "foundation-266-following-window-inventory-v1",
        SUCCESSOR_266.unit: "foundation-266-successor-window-inventory-v1",
    }.get(scope.unit, "foundation-266-window-inventory-v1")
    remote = inventory(kit, epoch=266, unit=inventory_unit)
    measured = current_fit(kit, roster, root, scope)
    floor = roster["capacity"]["guard_floor_bytes"]
    node = profile["node"]["path"]
    with tempfile.TemporaryDirectory(dir=state / "evidence") as staging:
        stage = Path(staging)
        admission_draft = ops.funds.put(stage / "admission.json", {
            "schema": "foundation-epoch266-private-window-admission-v1", "epoch": 266,
            "recorded_unix_seconds": int(time.time()), "producer_unit": scope.unit,
            "run_root": str(root), "node_sha256": profile["node"]["sha256"],
            "minimum_free_bytes": floor, "source_window_sha256": profile["node_plan_inputs"]["source_window"]["sha256"],
            "profile": scope.profile, "preflight": scope.preflight, "roster": roster_ref,
            "fit": measured, "inventory": remote, "admitted": True,
            "complete_fleet_and_century_floor_bound": True, "startup_guard_qualified": True,
            "publication_authorized": False,
        })
        admission = dict(admission_draft, path=str(plan_path / "admission.json"))
        draft = ops.funds.put(stage / "node_plan.json", dict(
            profile["node_plan_inputs"], admission=admission, minimum_free_bytes=floor))
        node_plan = dict(draft, path=str(plan_path / "node_plan.json"))
        deployment = ops.funds.put(stage / "deployment.json", {
            "schema": "jetstreamer-sealed-deployment-plan-v1", "destination": str(plan_path),
            "members": [dict(source=item["path"], name=Path(item["path"]).name,
                             sha256=item["sha256"], mode=0o444) for item in (admission_draft, draft)],
        })
        sealer = {"path": str(V / "horizon251-published-sealer-20261118-v1/horizon251-sealer"),
                  "sha256": "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a"}
        subprocess.run([ops.checked_image(sealer), deployment["path"], "--plan-sha256", deployment["sha256"],
                        "--self-sha256", sealer["sha256"]], check=True, timeout=20, umask=0o022)
    assert ops.ref(Path(node_plan["path"])) == node_plan and ops.ref(Path(admission["path"])) == admission
    prior = ops.bound(OVERLAP_266.profile)
    private_state = root / "state"
    if not private_state.exists():
        private_state.mkdir(mode=0o700)
        os.chown(private_state, 1000, 1000)
    metadata = private_state.lstat()
    assert private_state.resolve() == private_state and stat.S_ISDIR(metadata.st_mode)
    assert metadata.st_uid == 1000 and metadata.st_mode & 0o777 == 0o700 and not any(private_state.iterdir())
    env = dict(prior["environment"], JETSTREAMER_PRIVATE_RUN_ROOT=str(private_state),
               TMPDIR=str(root / "scratch"), CLOUDSDK_CONFIG=str(root / "scratch/isolated-empty-gcloud"))
    assert env["JETSTREAMER_HISTORICAL_WORKER_V1_8_11"] == profile["worker"]["path"]
    properties = dict(profile["properties"], BindReadOnlyPaths=" ".join(bindings),
                      ReadOnlyPaths=f"{tokens} {plan_path}", OOMPolicy="kill",
                      TimeoutStartSec="180",
                      UnsetEnvironment="HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL")
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in env.items())
    argv = [node, "266", str(root / "ledger"), "--verify",
            "--checkpoint-continuation-plan=" + node_plan["path"],
            "--checkpoint-continuation-plan-sha256=" + node_plan["sha256"]]
    template = ops.bound(profile["static_guard_plan"])
    assert template["minimum_free_bytes"] == floor and template["receipt_directory"] == str(state / "guard-receipts")

    def confirm_held(held, plan, sample, clock, next_tick):
        assert sample["producer_invocation_id"] == held["InvocationID"]
        assert sample["plan_sha256"] == plan["sha256"] and sample["trip_reason"] is None
        assert clock["ActiveState"] == "active" and next_tick > time.monotonic_ns() // 1000
        assert ops.props(scope.guard, ["AllowedCPUs", "MemoryMax"]) == {
            "AllowedCPUs": "30", "MemoryMax": str(profile["guard_memory_bytes"])}
        process = Path("/proc") / held["ControlPID"]
        namespace = process / "root"
        for view in views:
            opened = namespace / Path(view["target"]).relative_to("/")
            info = opened.stat()
            assert os.statvfs(opened).f_flag & os.ST_RDONLY
            assert (info.st_dev, info.st_ino, info.st_size) == tuple(view[key] for key in ("device", "inode", "bytes"))
        if projection is not None:
            mounted_custody = namespace / Path(projection["host_custody"]["path"]).relative_to("/")
            assert os.statvfs(mounted_custody).f_flag & os.ST_RDONLY
            assert mounted_custody.samefile(projection["source_custody"]["path"])
            assert ops.ref(mounted_custody)["sha256"] == custody["sha256"]
        scratch = root / "scratch"
        mounted, = (line.split(" - ", 1)[1].split()
                    for line in (process / "mountinfo").read_text().splitlines()
                    if line.split()[4] == str(scratch))
        assert mounted[0] == "tmpfs" and "noswap" in mounted[2].split(",")
        stats = os.statvfs(namespace / scratch.relative_to("/"))
        assert stats.f_frsize * stats.f_blocks == profile["scratch_tmpfs_bytes"]
        confirmation = current_fit(kit, roster, root, scope, held=True)
        ops.funds.put(state / "guard-release-fit.json", {
            "schema": "foundation-epoch266-private-window-guard-release-fit-v1",
            "invocation_id": held["InvocationID"], "roster": roster_ref, "guard_plan": plan,
            "node_plan": node_plan, "fit": confirmation, "publication_authorized": False,
        })

    owner, plan, token, guard = activate_guarded(
        kit, 266, state, tokens, scope.unit, scope.guard, profile["guard"], template, admission,
        props, f"ExecStartPre=/usr/bin/bash {hook} 60 {tokens}", argv,
        guard_cpuset="30", before_release=confirm_held)
    return ops.funds.put(state / "cadence-registration.json", {
        "schema": "jetstreamer-historical-performance-launch-receipt-v1",
        "kind": scope.kind, "epoch": 266, "unit": scope.unit, "run_root": str(root),
        "invocation_id": owner["invocation_id"], "main_pid": owner["main_pid"],
        "node_path": node, "worker": profile["worker"], "profile": scope.profile,
        "admission": admission, "node_plan": node_plan, "bootstrap_custody": custody,
        "guard_plan": plan, "active_guard": guard, "launch_token": token,
        "guard_release_fit": ops.ref(state / "guard-release-fit.json"), "evidence": {"units": [owner]},
        "launched": True, "diagnostic_only": True, "predecessor_native_tuple_qualified": False,
        "cursor_normalization_qualified": False, "canonical_epoch_publication_authorized": False,
        "remote_mutations": False, "r2_mutations": False,
    })


def launch(kit, roster_ref, scope):
    if scope in (WINDOW_266, SUCCESSOR_266, FOLLOWING_266):
        return launch_window_266(kit, roster_ref, scope)
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
    if scope is SUCCESSOR_REPLAY_230:
        tokens = V / "horizon230-successor-99516304-tokens-v1"
    if scope is V1627_230:
        tokens = V / "horizon230-v1627-tokens-v1"
    if scope is ADJACENT_230:
        tokens = V / "horizon230-adjacent-99445304-tokens-v1"
    if scope is NEXT_V1627_230:
        tokens = V / "horizon230-next-v1627-window-tokens-v1"
    if scope is RETRY_NEXT_V1627_230:
        tokens = V / "horizon230-next-v1627-retry-tokens-v2"
    assert not (state / "cadence-registration.json").exists()
    assert not (attempt / "admission.json").exists()
    if scope is OVERLAP_266:
        tokens = epoch266_overlap.TOKENS
    if scope is PREDECESSOR_266:
        tokens = V / "horizon266-original-predecessor-tokens-v1"
    qualify_tokens = failed_start is not None or scope in (SECOND_HOURLY_230, *BRIDGE_230,
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
    if scope in NEXT_V1627_SCOPES:
        current_fit(kit, roster, root, scope)
    if scope is OVERLAP_266:
        epoch266_overlap.validate_sources()
        assert profile == json.loads(epoch266_overlap.files()["profile.json"])
    node = profile["node"]["path"]
    hook = ops.checked_image(HOOK)
    if scope is PREDECESSOR_266:
        namespace, bootstrap = predecessor_namespace(ops, scope, preflight, profile)
    elif scope in NEXT_V1627_SCOPES:
        assert preflight["profile"] == scope.profile and preflight["worker_execution"] is False
        assert preflight["bootstrap_custody"] == profile["bootstrap_custody"]
        assert preflight["readonly_bindings_validated"] and preflight["writable_private_state_validated"]
        if scope is RETRY_NEXT_V1627_230:
            assert profile["prior_failed_start"] == preflight["prior_failed_start"] == NEXT_V1627_FAILED_START
            worker = ops.bound(profile["worker_build"])
            assert preflight["worker_build"] == profile["worker_build"]
            assert worker["artifact_sha256"] == profile["worker"]["sha256"]
            assert worker["bootstrap"] == 99_468_089 and worker["last_slot"] == 99_476_782
            acceptance_path = RETRY_NEXT_V1627_230_FLEET
            acceptance_schema = "foundation-epoch230-next-v1627-retry-fleet-release-v2"
        else:
            acceptance_path = NEXT_V1627_230_FLEET
            acceptance_schema = "foundation-epoch230-next-v1627-fleet-release-v1"
        acceptance = ops.bound(ops.ref(acceptance_path))
        assert acceptance["schema"] == acceptance_schema
        assert acceptance["preflight"] == scope.preflight and acceptance["admission_authorized"] is False
        ops.checked_image(acceptance["fleet"])
        for key, actual in (("adapter", CONTROL / ADAPTER), ("cycle", CONTROL / "cycle.py"),
                            ("status", CONTROL / "focused_foundation_status.py"),
                            ("launcher", Path(__file__))):
            saved = acceptance[key]
            assert ops.ref(Path(saved["path"])) == saved
            assert actual.read_bytes() == Path(saved["path"]).read_bytes()
        projection = ops.bound(preflight["mount_preflight"])
        assert projection["worker_execution"] is False and projection["uid"] == 1000
        assert all(view["readonly"] for view in projection["views"])
        namespace = {"mounted_device_inode_size": [
            f'{view["device"]}:{view["inode"]}:{view["bytes"]}' for view in projection["views"]]}
        bootstrap = ops.bound(profile["bootstrap_custody"])["bootstrap"]
        assert all(bootstrap[key] == profile["bootstrap"][key] for key in ("path", "sha256", "inode"))
        stat_bootstrap = Path(bootstrap["path"]).stat()
        assert stat_bootstrap.st_uid == 0 and not stat_bootstrap.st_mode & 0o222
        bootstrap["identity"] = (
            f"{bootstrap['device']}:{bootstrap['inode']}:{bootstrap['size']}:"
            f"{bootstrap['mtime_ns'] // 1_000_000_000}:{bootstrap['ctime_ns'] // 1_000_000_000}")
    else:
        namespace = ops.bound(ops.ref(state / "namespace.json"))
        bootstrap = ops.bound(ops.ref(state / "bootstrap-recheck.json"))["bootstrap"]
        if scope is SUCCESSOR_REPLAY_230:
            assert preflight["profile"] == scope.profile and preflight["worker_execution"] is False
            assert preflight["private_namespace_validated"]
            assert preflight["bootstrap_custody"] == profile["bootstrap_custody"]
            custody = ops.bound(profile["bootstrap_custody"])
            assert custody["copy_drained"] and custody["whole_file_sha256_rechecked"]
            assert all(bootstrap[key] == custody["input"][key] for key in ("path", "sha256"))
            assert ops.bound(preflight["guard_validation"])["plan_sha256"] == profile["static_guard_plan"]["sha256"]
            assert ops.ref(Path(profile["epoch_hashes"]["path"])) == profile["epoch_hashes"]
        elif scope is ADJACENT_230:
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
        if scope in BRIDGE_230:
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
        elif scope is SUCCESSOR_REPLAY_230:
            probe_unit = "foundation-230-successor-99516304-token-probe-v1"
        elif scope is V1627_230:
            probe_unit = "foundation-230-v1627-token-probe-v1"
        elif scope is ADJACENT_230:
            probe_unit = "foundation-230-adjacent-99445304-token-probe-v1"
        elif scope in NEXT_V1627_SCOPES:
            probe_unit = ("foundation-230-next-v1627-retry-token-probe-v2"
                          if scope is RETRY_NEXT_V1627_230 else "foundation-230-next-v1627-token-probe-v1")
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
