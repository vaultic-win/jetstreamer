"""Launch the private, rooted middle segment after stock-worker qualification."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

import epoch288_shrink_debt_comparison as capacity
from epoch230_checkpoint_continuation_launch import activate_guarded, inventory


STATE = capacity.V / "horizon230-middle-fit-v1"
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-230-middle-v1")
TOKENS = capacity.V / "horizon230-middle-tokens-v1"
BOOTSTRAP = capacity.V / "horizon230-middle-stock-bootstrap-v1"
RELEASE = capacity.V / "horizon230-middle-fleet-v1"
UNIT = "horizon-qualify-230-middle-v1.service"
GUARD = "horizon-230-middle-protective-v1.service"
CAP = 625_000_000_000
MEMORY = 225_000_000_000
FLOOR = 3_770_104_987_645
WORKER_SHA = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"


def fresh_fit(ops):
    basis_ref = ops.ref(STATE / "phase-fit.json")
    basis = ops.bound(basis_ref)
    assert basis["producer_disk_bytes"] == CAP and basis["producer_memory_bytes"] == MEMORY
    trace = "foundation-296-meter-trace-build-v2.service"
    assert ops.props(trace, ["ActiveState", "MainPID"]) == {"ActiveState": "inactive", "MainPID": "0"}
    expected = {unit: row for unit, row in basis["owners"].items() if unit != trace}
    census = subprocess.check_output([
        "systemctl", "list-units", "--type=service", "--state=running,activating",
        "--plain", "--no-legend", "--no-pager",
    ], text=True, timeout=10)
    listed = {line.split()[0] for line in census.splitlines() if line.startswith(("horizon-", "foundation-"))}
    assert listed == set(expected), (listed, set(expected))
    owners = {}
    for unit, prior in expected.items():
        row = ops.props(unit, ["Id", "InvocationID", "ActiveState", "SubState",
                               "AllowedCPUs", "MemoryMax", "MemoryCurrent"])
        assert (row["Id"], row["ActiveState"], row["SubState"]) == (unit, "active", "running")
        assert all(row[key] == prior[key] for key in ("InvocationID", "MemoryMax", "AllowedCPUs"))
        owners[unit] = row
    mem = {key: int(value.split()[0]) * 1024 for key, value in
           (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
           if key in ("MemTotal", "MemAvailable")}
    growth = sum(max(0, int(row["MemoryMax"]) - int(row["MemoryCurrent"])) for row in owners.values())
    available = min(mem["MemAvailable"] - mem["MemTotal"] // 10 - growth,
                    basis["memory_available_for_candidate_bytes"])
    assert ROOT.stat().st_dev == Path("/").stat().st_dev
    fs = os.statvfs(ROOT)
    free = fs.f_bavail * fs.f_frsize
    disk_left = free - basis["disk_protected_bytes"] - basis["staging_bytes"] - CAP
    memory_left = available - MEMORY - (1 << 30)
    assert disk_left >= 0 and memory_left >= 0, (disk_left, memory_left)
    return dict(basis=basis_ref, owners=owners, free_bytes=free, disk_margin_bytes=disk_left,
                memory_margin_bytes=memory_left, cpus="72-79")


def start(kit):
    ops = kit.ops
    for name in (UNIT, GUARD, GUARD.replace(".service", ".timer")):
        assert ops.props(name, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    inputs_ref = ops.ref(STATE / "inputs.json")
    inputs = ops.bound(inputs_ref)
    namespace = ops.ref(STATE / "namespace-qualification.json")
    assert ops.bound(namespace)["inputs"] == inputs_ref
    boot_ref = ops.ref(BOOTSTRAP / "terminal.json")
    boot = ops.bound(boot_ref)
    native = boot["native"]
    assert native["checkpoint_matched"] and native["worker_sha256"] == WORKER_SHA
    assert native["actual"]["slot"] == 99_383_572 and native["replay_entries_sent"] == 0
    assert native["worker_shutdown_succeeded"] and native["snapshot_sha256"] == inputs["bootstrap"]["sha256"]
    assert boot["producer"]["Result"] == "success" and boot["producer"]["MainPID"] == "0"
    assert inputs["canonical_span"] == [99_383_573, 99_791_404]
    assert inputs["worker"]["sha256"] == WORKER_SHA
    assert not list((ROOT / "private").iterdir())
    output_dir = ROOT / "output"
    destination = output_dir / "epoch-230-middle.jet"
    assert not destination.exists()
    node = capacity.checked(inputs["node"])
    worker = capacity.checked(inputs["worker"])
    release_ref = ops.ref(RELEASE / "acceptance.json")
    released = ops.bound(release_ref)
    assert released["schema"] == "foundation-epoch230-middle-fleet-release-v1"
    capacity.checked(released["fleet"])
    kit.startup.until(lambda: ops.props("foundation-publication-cadence-v222.service", ["ActiveState"])[
        "ActiveState"] == "inactive", 2)
    remote = inventory(kit, unit="foundation-230-middle-inventory-v1")
    guard = capacity.read(capacity.binding(capacity.V / "horizon230-full-v291/profile.json"))["guard"]
    capacity.checked(guard)
    template = dict(schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=UNIT,
                    invocation_id="0" * 32, filesystem="/", worker_root=str(ROOT),
                    receipt_directory=str(STATE / "guard-receipts"), maximum_worker_vmas=3_500_000,
                    minimum_free_bytes=FLOOR, maximum_root_physical_bytes=CAP)
    plan = ops.funds.put(STATE / "static-guard-plan.json", template)
    disarmed = json.loads(subprocess.check_output([
        guard["path"], plan["path"], "--plan-sha256", plan["sha256"],
        "--self-sha256", guard["sha256"], "--validate-plan-only",
    ], timeout=20))
    assert disarmed["validated"] and disarmed["unit"] == UNIT and not disarmed["producer_signaled"]
    hook = capacity.V / "horizon230-final-tail-tokens-v1/pre-start.sh"
    assert hook.stat().st_uid == 0 and not hook.stat().st_mode & 0o222
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    gcloud = ROOT / "tmp/isolated-empty-gcloud"
    gcloud.mkdir(mode=0o700)
    os.chown(gcloud, 1000, 1000)
    environment = {
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME": "1", "JETSTREAMER_CLEAR_ACCOUNTS_ON_START": "1",
        "JETSTREAMER_ENFORCE_ARCHIVE_HASH": "1", "JETSTREAMER_PRIVATE_RUN_ROOT": str(ROOT / "private"),
        "JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS": "0", "JETSTREAMER_SKIP_SNAPSHOT_VERIFY": "0",
        "JETSTREAMER_VERIFY_SNAPSHOTS": "1", "RUST_LOG": "info", "JETSTREAMER_RIPGET_THREADS": "1",
        "JETSTREAMER_NETWORK": "mainnet", "SOLANA_RAYON_THREADS": "8", "RAYON_NUM_THREADS": "8",
        "JETSTREAMER_HISTORICAL_POH_THREADS": "8", "TOKIO_WORKER_THREADS": "8",
        "JETSTREAMER_REPLAY_THREADS": "8", "RUST_MIN_STACK": "134217728",
        "TMPDIR": str(ROOT / "tmp"), "CLOUDSDK_CONFIG": str(gcloud), "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "1", "JETSTREAMER_FORCE_LEGACY_INDEX": "1",
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_20": str(worker),
    }
    properties = {
        "Type": "exec", "User": "ubuntu", "Group": "ubuntu", "UMask": "0077", "Restart": "no",
        "KillMode": "control-group", "AllowedCPUs": "72-79", "CPUQuota": "800%", "MemoryMax": str(MEMORY),
        "MemorySwapMax": "0", "RuntimeMaxSec": "432000", "TasksMax": "2048",
        "ProtectSystem": "strict", "ProtectHome": "read-only", "NoNewPrivileges": "yes",
        "WorkingDirectory": str(ROOT), "ReadWritePaths": str(ROOT), "TimeoutStartSec": "120",
        "BindReadOnlyPaths": " ".join(f"{pin['path']}:{path}" for path, pin in inputs["bindings"].items()),
    }
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in environment.items())
    prestart = f"ExecStartPre=/usr/bin/bash {hook} 60 {TOKENS}"
    argv = [str(node), "230", str(output_dir), "--verify", f"--snapshot-archive={inputs['bootstrap']['path']}",
            f"--epoch-hashes={ROOT / 'epoch-hashes.txt'}", "--qualification-end-slot=99791404",
            f"--horizon-output={destination}"]
    fit = fresh_fit(ops)
    admission = ops.funds.put(STATE / "admission.json", dict(
        schema="foundation-epoch230-middle-admission-v1", epoch=230, inputs=inputs_ref,
        bootstrap=boot_ref, namespace=namespace, node=inputs["node"], worker=inputs["worker"],
        fleet_tool=release_ref, argv=argv, properties=properties, fit=fit, inventory=remote,
        static_guard_validation=disarmed, admitted=True, publication_authorized=False))
    owner, guard_plan, token, active_guard = activate_guarded(
        kit, 230, STATE, TOKENS, UNIT, GUARD, guard, template, admission, props, prestart, argv)
    return ops.funds.put(STATE / "cadence-registration.json", dict(
        schema="jetstreamer-historical-performance-launch-receipt-v1", kind="epoch230-middle-continuation",
        epoch=230, unit=UNIT, invocation_id=owner["invocation_id"], main_pid=owner["main_pid"],
        node_path=str(node), run_root=str(ROOT), worker_sha256=WORKER_SHA,
        bootstrap_slot=99_383_572, first_slot=99_383_573, last_slot=99_791_404, launched=True,
        entry_replay_requested=True, canonical_epoch_publication_authorized=False,
        full_continuation_peak_qualified=False, remote_mutations=False, r2_mutations=False,
        admission=admission, guard_plan=guard_plan, launch_token=token,
        active_guard=active_guard, evidence={"units": [owner]}))


def main():
    assert os.geteuid() == 0 and __debug__
    kit = capacity.load_existing()
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    os.umask(0o077)
    with kit.partition.take(), (capacity.CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        print(json.dumps(start(kit)))


if __name__ == "__main__":
    main()
