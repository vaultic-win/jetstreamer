"""Bind the epoch 143 probe to the existing single bounded native entry slot."""

import hashlib
from pathlib import Path
import re

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-bounded-entry-20261126-v1")
VIEW = Path("/var/lib/jetstreamer/horizon-epoch143-bounded-entry-20261126-v1")
FIELD = "epoch143_bounded_entry_lease"
LEASE = ROOT / "BOUNDED_ENTRY_LEASE.json"
PREFLIGHT = VIEW / "static/STATIC_ENTRY_PREFLIGHT.json"
MANIFEST = VIEW / "manifest/preflight-143-v4.json"
UNIT = "horizon-143-full-local-qualification-20261126-v1.service"
GROUP = "/horizonaudit.slice/" + UNIT
RUN = Path("/home/sol/.jetstreamer-private/epoch143-standard-lane-20261126-v1/full-local-v1")
BOOTSTRAP = Path("/home/sol/.jetstreamer-private/epoch143-bootstrap-20261126.rJJV8Spl/snapshot-61775538-65YRW5KRaq6JezqoEc9rUqnmgfp7TjVw3koFbnMtbuun.tar.zst")
DEPLOYMENT = Path("/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1")
NODE = DEPLOYMENT / "jetstreamer-node"
WORKER = DEPLOYMENT / "jetstreamer-historical-worker-v1-4-25"
GENESIS = Path("/usr/local/lib/jetstreamer/horizon-standard-local-input172-20261110-v1/genesis.tar.bz2")
CUSTODY = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-bootstrap-custody-20261126-v1/INPUT_CUSTODY.json")
LAUNCHER = VIEW / "launcher/hold-entry143"
LAUNCHER_SEAL = LAUNCHER.with_name("deployment-seal-receipt.json")
FINGERPRINT = "sha256:802ce7ae600d5942e1d7e73c66e845a550628a60bf5bdcb519cdeb57e8445fcf"
CUSTODY_REF = dict(path=str(CUSTODY), sha256="667d821dfaf67d6be8fd8076cf6c420cadf4d71b0b8229703716894535748a93")
SNAPSHOT_SHA = "ac658ca76799e6564a9e4fc8c2974618c87307ea798a89061d42fc01c8df727c"
MANIFEST_SHA = "f5848245419e730ba0df782215291a40ad278a5f7776254374f13eb129f270cb"
GENESIS_SHA = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
RUNTIME = {
    "node": dict(path=str(NODE), sha256="a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"),
    "worker": dict(path=str(WORKER), sha256="2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"),
    "genesis": dict(path=str(GENESIS), sha256=GENESIS_SHA),
}
FILES = (
    (BOOTSTRAP, RUN / "inputs" / BOOTSTRAP.name, SNAPSHOT_SHA),
    (MANIFEST, RUN / "inputs" / MANIFEST.name, MANIFEST_SHA),
    (GENESIS, RUN / "ledger/genesis.tar.bz2", GENESIS_SHA),
)
ARGV = [str(NODE), "143", str(RUN / "ledger"), "--verify", "--root-checkpoint-cohort",
        f"--cohort-manifest={FILES[1][1]}", f"--cohort-manifest-fingerprint={FINGERPRINT}",
        f"--snapshot-archive={FILES[0][1]}"]
ENVIRONMENT = {
    "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME": "1",
    "JETSTREAMER_ARCHIVE_BACKEND": "http",
    "JETSTREAMER_CLEAR_ACCOUNTS_ON_START": "true",
    "JETSTREAMER_COMPACT_INDEX_BASE_URL": "https://files.old-faithful.net/",
    "JETSTREAMER_ENFORCE_ARCHIVE_HASH": "1",
    "JETSTREAMER_HISTORICAL_POH_THREADS": "10",
    "JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS": "600",
    "JETSTREAMER_HISTORICAL_WORKER_V1_4_25": str(WORKER),
    "JETSTREAMER_HTTP_BASE_URL": "https://files.old-faithful.net/",
    "JETSTREAMER_LOAD_FROM_DIR": "0",
    "JETSTREAMER_NETWORK_CAPACITY_MB": "1024",
    "JETSTREAMER_PRIVATE_RUN_ROOT": str(RUN / "private"),
    "JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS": "0",
    "JETSTREAMER_RIPGET_THREADS": "12",
    "JETSTREAMER_SKIP_SNAPSHOT_VERIFY": "0",
    "JETSTREAMER_THREADS": "12",
    "JETSTREAMER_VERIFY_SNAPSHOTS": "1",
    "RAYON_NUM_THREADS": "10",
    "SOLANA_RAYON_THREADS": "32",
    "RUST_LOG": "info,solana_metrics=off",
    "TOKIO_WORKER_THREADS": "2",
}
NOEXEC = "/home/sol /usr/local/lib/jetstreamer /usr/local/bin /usr/lib/google-cloud-sdk"


def validate_preflight(s, preflight):
    s.need(preflight["schema"] == "horizon-epoch143-bounded-static-entry-v1"
           and preflight["planned_native_unit"] == UNIT
           and preflight["planned_argv"] == ARGV
           and preflight["planned_environment"] == ENVIRONMENT
           and preflight["runtime"] == RUNTIME
           and preflight["manifest_fingerprint"] == FINGERPRINT
           and preflight["root_checkpoints"] == [{
               "slot": 62207522, "generation": 1634786803341628,
               "accounts_hash": "4mbMh5MmABcciZVz1BTXCTCZ4th1mCufadrLUUVVs52x",
           }]
           and preflight["snapshot_generation"] == 1634786753953981
           and preflight["snapshot_custody"] == CUSTODY_REF
           and preflight["replay_slots_inclusive"] == [61775539, 62207999]
           and preflight["archive_slots_inclusive"] == [61776000, 62207999]
           and preflight["isolated_mount_test_passed"] is True
           and preflight["native_node_invoked"] is False
           and preflight["historical_worker_invoked"] is False
           and preflight["replay_admission_granted"] is False,
           "different bounded epoch 143 source, scope or startup route")
    mounts = preflight["observed_mounts"]
    s.need(len(mounts) == len(FILES) and preflight["planned_bind_read_only_paths"] ==
           [f"{source}:{target}" for source, target, _ in FILES], "different epoch 143 mount set")
    for binding, (source, target, digest) in zip(mounts, FILES, strict=True):
        s.need(binding["source"] == str(source) and binding["planned_target"] == str(target)
               and binding["sha256"] == digest and binding["read_only"] is True
               and binding["readable_as_sol_horizon"] is True,
               "changed bounded epoch 143 input")
    snapshot = mounts[0]["identity"]
    s.need((snapshot["device"], snapshot["inode"], snapshot["bytes"], snapshot["mtime_ns"]) ==
           (64512, 118554661, 3714834246, 1795715033665183475), "different epoch 143 snapshot inode")
    launcher = preflight["held_launcher"]
    s.need(launcher == {"path": str(LAUNCHER)}
           and preflight["held_argv"] == [str(LAUNCHER)], "different held epoch 143 executable")
    return preflight


def lease(s, lease_ref, *, boot=None):
    record = s.bound(lease_ref, LEASE)
    preflight = validate_preflight(s, s.bound(record["preflight"], PREFLIGHT))
    if boot is None:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    iid, pid, start = record["invocation_id"], record["pid"], record["start_ticks"]
    s.need(record["schema"] == "horizon-epoch143-bounded-entry-lease-v1" and record["boot"] == boot
           and record["unit"] == UNIT and type(pid) is int and 2 <= pid < (1 << 31)
           and type(start) is int and start > 0 and isinstance(iid, str)
           and re.fullmatch("[0-9a-f]{32}", iid) and int(iid, 16), "different bounded epoch 143 lease")
    return dict(unit=UNIT, invocation_id=iid, pid=pid, start_ticks=start, memory_bytes=192 << 20,
                scratch_bytes=8 << 20, additional_cpu_quota_micros=0, registration=lease_ref), preflight, boot


def reservation(s, lease_ref):
    return lease(s, lease_ref)[0]


def manager_settings(claim):
    pid = str(claim["pid"])
    return dict(Id=UNIT, InvocationID=claim["invocation_id"], ExecMainPID=pid, MainPID=pid,
                ControlPID="0", ActiveState="active", SubState="running", Job="", NRestarts="0",
                ControlGroup=GROUP, Slice="horizonaudit.slice", User="sol", Group="horizon",
                MemoryMax=str(192 << 20), MemorySwapMax="0", CPUQuotaPerSecUSec="250ms",
                TasksMax="64", RuntimeMaxUSec="8min", ProtectHome="read-only", ProtectSystem="strict",
                PrivateNetwork="yes", PrivateDevices="yes", ProtectControlGroups="yes",
                NoNewPrivileges="yes", CapabilityBoundingSet="", LimitFSIZE=str(2 << 20),
                LimitFSIZESoft=str(2 << 20), NoExecPaths=NOEXEC, ExecPaths=str(NODE),
                BindReadOnlyPaths=" ".join(f"{source}:{target}:rbind" for source, target, _ in FILES))


def check_inputs(s, preflight):
    for binding in preflight["observed_mounts"]:
        source = Path(binding["source"])
        saved = binding["identity"]
        info = source.stat()
        s.need(source.resolve(strict=True) == source and
               (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns, info.st_mtime_ns)
               == tuple(saved[key] for key in ("device", "inode", "bytes", "ctime_ns", "mtime_ns")),
               "bounded epoch 143 input changed")


def held(s, lease_ref, shared):
    claim, preflight, _ = lease(s, lease_ref)
    check_inputs(s, preflight)
    proc = Path("/proc") / str(claim["pid"])
    with (proc / "exe").open("rb") as image:
        digest = hashlib.file_digest(image, "sha256").hexdigest()
    seal, _ = s.read(LAUNCHER_SEAL)
    sealed, = [member for member in seal["members"] if member["name"] == LAUNCHER.name]
    s.need(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
           and seal["destination"] == str(LAUNCHER.parent) and sealed["mode"] == "0555"
           and (proc / "exe").samefile(LAUNCHER) and digest == sealed["sha256"],
           "different held epoch 143 process image")
    return shared["verify_held"](s, claim, preflight, UNIT, GROUP)


def terminal(claim, shared):
    return shared["verify_terminal"](claim, UNIT, GROUP)


def observe(s, pid, comm, start, group, lease_ref, shared):
    if (comm, group) != ("jetstreamer-nod", "0::" + GROUP):
        return None
    claim, preflight, boot = lease(s, lease_ref)
    s.need((claim["pid"], claim["start_ticks"]) == (pid, start), "different bounded epoch 143 process")
    if terminal(claim, shared):
        return claim
    check_inputs(s, preflight)
    route = dict(argv=ARGV, run_parent=str(RUN), worker=RUNTIME["worker"],
                 snapshot={"target": str(FILES[0][1])},
                 read_only_file_binds=preflight["planned_bind_read_only_paths"])
    expected = dict(manager=manager_settings(claim), pid=pid, boot=boot, cgroup=group, members=[pid],
                    comm=comm, argv=ARGV, exe=str(NODE), image=shared["file_identity"](NODE),
                    image_digest=RUNTIME["node"]["sha256"], uid=[1001]*4, gid=[1003]*4,
                    fs_limit=[2 << 20]*2, worker_noexec=True, private_network=True,
                    snapshot=shared["file_identity"](BOOTSTRAP), inputs_readonly=True,
                    inputs_match=True, scratch_bytes=8 << 20, scratch_tmpfs=True)
    try:
        shared["verify_live"](s, route, expected, start)
    except (FileNotFoundError, ProcessLookupError):
        if not terminal(claim, shared):
            raise
    return claim
