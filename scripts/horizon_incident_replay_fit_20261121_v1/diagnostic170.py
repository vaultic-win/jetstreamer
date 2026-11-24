"""Offline preparation and an invocation-bound gate for the epoch 170 diagnostic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

HOME = Path("/home/sol")
LANE = HOME / ".jetstreamer-private/epoch170-standard-lane-20261109-v1"
ANCESTOR = LANE / "replacement-local3retry7-20261110-v1"
RUN = ANCESTOR / "replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1"
OPS = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-metered-hourly-20261124-v1")
ALIAS = Path("/run/horizon-170-metered-hourly-v1")
UNIT = "horizon-qualify-170-metered-hourly-20261124-v1.service"
GUARD_SERVICE = "horizon-guard-170-metered-hourly-20261124-v1.service"
TIMER = GUARD_SERVICE.replace(".service", ".timer")
CGROUP = f"/system.slice/{UNIT}"
OLD_OPS = OPS.parent / "epoch170-retry13-rebook-20261122-v1"
OLD_EVENT = OLD_OPS / "failed-replay-20261124T123309Z"
NODE = Path("/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-node")
WORKER = OPS.parent / "epoch172-full-replay-20261120-v1/inputs-v1/jetstreamer-historical-worker-v1-5-6"
GUARD = OPS.parent / "epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
GENESIS = Path("/usr/local/lib/jetstreamer/horizon-standard-local-input170-20261110-v1/genesis.tar.bz2")
NODE_SHA = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
WORKER_SHA = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541"
GUARD_SHA = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
GENESIS_SHA = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
SOURCE_BASE = "gs://mainnet-beta-ledger-us-ny5/"
CAR = "https://files.old-faithful.net/170/epoch-170.car"
EPOCH_CID = "bafyreia7an3ku7nhc6mwpqygmsldmq25yli5urrrtf4j75u7k4zwx2psc4"
INDEX_ROOT = ANCESTOR / "replacement-local3retry9-20261110-v1/output/compact-indexes/170"
INDEX_NAMES = {
    f"epoch-170-{EPOCH_CID}-mainnet-slot-to-cid.index",
    f"epoch-170-{EPOCH_CID}-mainnet-cid-to-offset-and-size.index",
}

TERMINAL = 73_713_261
BOOTSTRAP = 73_706_460
START_HASH = "3SF9c2ZeGqa8bL3mbVzeNeGNPCBgFBZCe2yj5r9pFUX7"
END_HASH = "2wr6xQzjdUwXgXG8kECpQpfrMdFXstqzQEHAJ85Xtq9g"
START_NAME = f"snapshot-{BOOTSTRAP}-{START_HASH}.tar.zst"
END_NAME = f"snapshot-{TERMINAL}-{END_HASH}.tar.zst"
SNAPSHOT = RUN / "inputs" / START_NAME
LEDGER = RUN / "ledger"
ARCHIVE = LEDGER / "epoch-170.diagnostic.jet"
MANIFEST = ARCHIVE.with_name(ARCHIVE.name + ".segment.json")
CHECKPOINTS = f"{START_NAME}\n{END_NAME}\n".encode()
SNAPSHOT_ROWS = [
    dict(name=f"73439777/hourly/{START_NAME}", generation="1634787456399441",
         size=2_132_143_835, crc32c_hash="hwq58Q==", md5_hash="bp2YghoqNZz/qwVEaMV0Fw=="),
    dict(name=f"73439777/hourly/{END_NAME}", generation="1634787458764347",
         size=2_131_964_199, crc32c_hash="NTm2pg==", md5_hash="garolMejDiw4LJeprTolEg=="),
]
CASE = dict(slot=73_711_515, entry=157, ordinal=191, entry_size=3, entry_offset=0,
            signature="4sGVN3wmFPNhxrnjyL7L9XER2HJTDq7VvjMauG56VTKUGQteUWek2WzSfnjEa2LvK5R8bkByo9VnPcM5BRyc9n6b",
            wire_sha256="d80e9633656b971d853d89971b6d27b1fb6234dfd52f5d1cb34b1cc8afd1dd14",
            metadata_sha256="65d7b720e82b58d277f14336039f9d80558eeeea2c4b8ef567b2b39b224c30bd",
            status=None, canonical_compute_units=199_964, limit=200_000, canonical_logs=43,
            compact_logs_sha256="3ccb88acc0919e81f832ea41e4b6a3cd8cd504b8d750f111f10099cf63e0d100",
            car=CAR, car_bytes=148_303_613_235, range_start=93_649_408_590, range_end=93_649_800_369,
            epoch_cid=EPOCH_CID, block_cid="bafyreigzzafnleeksyy3e6h4pffk7w6qzv5eti5rgtt75c6goo2kjnpmte",
            transaction_cid="bafyreieaovf5qz25drqkfi77bwq5e24yphpcodjdvvvs2qv453mpdyjq74",
            segment_sha256="56a9d7239d0d820b820fdfbc7af937c8ad09df284e8840a8936d6a9b53e56a42")
OLD_PROOFS = {
    OLD_OPS / "PREPARED.json": "e1759214d8f4865bd42d7992786d5b41e7ecebd25424ecc68d239c5d003a5ab3",
    OLD_OPS / "ACTUAL_ADMISSION_AND_PROTECTION.json": "f2748f58c5432fd8ccda6f5ad49b92dbdd01b7aa682558fd23230b8bc04e92a8",
    OLD_OPS / "ACTUAL_GUARD_PLAN.json": "c5322bbde82fdcfdd0b48b57ac0ebba6d439d8da4e3b622dbafe2b6a0618c31a",
    OLD_EVENT / "TERMINAL.json": "16664fda43d296d115858ff67a173d6d0cccb5f2ac90d446aa797da34a2f6c9d",
    OLD_EVENT / "ORPHAN_GUARD_DRAINED.json": "e570c630afe4add0209a6af6ebd9da6cc0195bc0a5b4034dcf2716baf130bae7",
}
GIB = 1 << 30
ROOT_BOOKING = 384 * GIB
DIAGNOSTIC_GROWTH = 96 * GIB
ACTOR_MEMORY = 68 * GIB
ACTOR_MEMORY_HIGH = 64 * GIB
VMA_LIMIT = 3_500_000
FIRST = BOOTSTRAP + 1
SLOT_COUNT = TERMINAL - BOOTSTRAP
GRANT_SCHEMA = "horizon-epoch170-metered-hourly-postguard-release-v1"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(d):
    return json.dumps(d, indent=2, sort_keys=True).encode() + b"\n"


def fingerprint(s, width=64):
    return isinstance(s, str) and re.fullmatch(f"[0-9a-f]{{{width}}}", s) and int(s, 16)


def identity(m):
    return [m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns]


def stable(path, *, root=False, immutable=True, limit=None, read_only=False):
    initial = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
         and not initial.st_mode & 0o022 and (not root or (initial.st_uid == 0 and (not immutable or not initial.st_mode & 0o222)))
         and (limit is None or initial.st_size <= limit), f"unsafe input {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as opened:
        need(identity(os.fstat(opened.fileno())) == identity(initial), f"replaced input {path}")
        if read_only:
            need(os.fstatvfs(opened.fileno()).f_flag & os.ST_RDONLY, f"not a read-only bind {path}")
        raw = opened.read(limit + 1) if limit is not None else None
        sha = hashlib.sha256(raw).hexdigest() if raw is not None else hashlib.file_digest(opened, "sha256").hexdigest()
        need(identity(os.fstat(opened.fileno())) == identity(initial) == identity(path.lstat()),
             f"unstable input {path}")
    return dict(path=str(path), identity=identity(initial), sha256=sha), raw


def pinned(path, sha, **kwargs):
    proof, raw = stable(path, **kwargs)
    need(proof["sha256"] == sha, f"wrong SHA-256 {path}")
    return proof, raw


def snapshot_metadata(actual, expected):
    need(all(actual.get(key) == value for key, value in expected.items()),
         f"GCS metadata differs for {expected['name']}")


def case_proof(path):
    h, _ = pinned(path, CASE["segment_sha256"], limit=1 << 20)
    need(h["identity"][2] == CASE["range_end"] - CASE["range_start"] + 1, "wrong CAR fragment length")
    return h


def root_shape():
    paths = [RUN, RUN / "inputs", RUN / "scratch", RUN / "tmp", RUN / "private", LEDGER]
    for path in paths:
        m = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISDIR(m.st_mode) and m.st_dev == HOME.stat().st_dev
             and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (1001, 1003, 0o700), f"unsafe work path {path}")
    for path in [RUN / "scratch", RUN / "tmp", RUN / "private"]:
        need(not any(path.iterdir()), f"occupied work path {path}")
    need(not os.path.lexists(ARCHIVE) and not os.path.lexists(MANIFEST), "diagnostic output exists")


def prepare(start_meta, end_meta, segment):
    root_shape()
    old = {str(path): pinned(path, sha, root=True, immutable=False, limit=128 << 10)[0]
           for path, sha in OLD_PROOFS.items()}
    metadata = []
    for source, expected in zip((start_meta, end_meta), SNAPSHOT_ROWS):
        meta_ref, raw = stable(source, limit=64 << 10)
        snapshot_metadata(json.loads(raw), expected)
        metadata.append(meta_ref)
    snap, _ = stable(SNAPSHOT)
    need(snap["identity"][2] == SNAPSHOT_ROWS[0]["size"], "wrong local snapshot size")
    [local_hashes] = json.loads(subprocess.check_output(
        ["/usr/lib/google-cloud-sdk/bin/gcloud", "storage", "hash", str(SNAPSHOT), "--format=json"], timeout=180,
        env={**os.environ, "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "1", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}))
    for key in ("crc32c_hash", "md5_hash"):
        need(local_hashes[key] == SNAPSHOT_ROWS[0][key], "local snapshot checksum mismatch")
    need(identity(SNAPSHOT.lstat()) == snap["identity"], "snapshot changed across hashes")
    genesis = pinned(GENESIS, GENESIS_SHA, root=True, limit=100_000)[0]
    index_receipt = json.loads(pinned(
        OLD_OPS / "PREPARED.json", OLD_PROOFS[OLD_OPS / "PREPARED.json"], root=True, limit=128 << 10)[1])
    indexes = []
    for row in index_receipt["indexes"]:
        path = Path(row["path"])
        if path.parent.name != "170":
            continue
        need(path.resolve(strict=True) == path and identity(path.lstat()) == row["identity"],
             f"retained compact index changed {path}")
        indexes.append(dict(path=str(path), identity=row["identity"], sha256=row["sha256"]))
    need(len(indexes) == 2 and {Path(row["path"]) for row in indexes} ==
         {INDEX_ROOT / name for name in INDEX_NAMES}, "wrong retained epoch 170 indexes")
    return dict(schema="horizon-epoch170-metered-hourly-inputs-v1",
                bootstrap=SNAPSHOT_ROWS[0], terminal=SNAPSHOT_ROWS[1], snapshot=snap, gcs_metadata=metadata,
                case=CASE, pinned_car=case_proof(segment), indexes=indexes, genesis=genesis,
                node=pinned(NODE, NODE_SHA, root=True)[0], worker=pinned(WORKER, WORKER_SHA, root=True)[0],
                guard=pinned(GUARD, GUARD_SHA, root=True)[0], predecessor=old,
                retained_booking_bytes=ROOT_BOOKING, private_growth_bytes=DIAGNOSTIC_GROWTH,
                canonical_publication_authorized=False)


def gate_plan(inputs):
    need(inputs["schema"] == "horizon-epoch170-metered-hourly-inputs-v1"
         and inputs["bootstrap"] == SNAPSHOT_ROWS[0] and inputs["terminal"] == SNAPSHOT_ROWS[1]
         and inputs["case"] == CASE and inputs["retained_booking_bytes"] == ROOT_BOOKING
         and inputs["private_growth_bytes"] == DIAGNOSTIC_GROWTH and inputs["canonical_publication_authorized"] is False,
         "foreign epoch 170 staging plan")
    need(all(inputs[name]["path"] == str(path) and inputs[name]["sha256"] == digest
             for name, path, digest in (("node", NODE, NODE_SHA), ("worker", WORKER, WORKER_SHA),
                                        ("guard", GUARD, GUARD_SHA), ("genesis", GENESIS, GENESIS_SHA))),
         "foreign executable or genesis")
    need(inputs["snapshot"]["path"] == str(SNAPSHOT) and
         inputs["snapshot"]["identity"][2] == SNAPSHOT_ROWS[0]["size"]
         and fingerprint(inputs["snapshot"]["sha256"]), "foreign snapshot proof")
    need(inputs["pinned_car"]["sha256"] == CASE["segment_sha256"]
         and inputs["pinned_car"]["identity"][2] == CASE["range_end"] - CASE["range_start"] + 1
         and len(inputs["gcs_metadata"]) == 2
         and all(fingerprint(row["sha256"]) for row in inputs["gcs_metadata"]), "missing canonical input proof")
    need({name: ref["sha256"] for name, ref in inputs["predecessor"].items()} ==
         {str(path): digest for path, digest in OLD_PROOFS.items()}, "foreign retained booking proof")
    need(len(inputs["indexes"]) == 2 and
         {Path(row["path"]) for row in inputs["indexes"]} == {INDEX_ROOT / name for name in INDEX_NAMES}
         and all(fingerprint(row["sha256"]) and len(row["identity"]) == 5 for row in inputs["indexes"]),
         "foreign epoch 170 compact index proofs")


def guard_plan(iid, floor, baseline):
    need(fingerprint(iid, 32) and 0 < baseline < ROOT_BOOKING and floor > 0
         and baseline + DIAGNOSTIC_GROWTH <= ROOT_BOOKING, "diagnostic growth or protected HOME floor is unqualified")
    return dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",
                unit=UNIT, invocation_id=iid, filesystem=str(HOME), minimum_free_bytes=floor,
                worker_root=str(LANE), maximum_worker_vmas=VMA_LIMIT,
                maximum_root_physical_bytes=baseline + DIAGNOSTIC_GROWTH,
                receipt_directory=str(OPS / "guard-receipts"))


def guard_command(plan, digest):
    need(plan == OPS / "guard-plan/guard-plan.json" and fingerprint(digest), "foreign guard plan")
    guard_root = OPS / "guard-receipts"
    return ["/usr/bin/systemd-run", "--on-active=1s", "--on-unit-inactive=5s",
            "--timer-property=AccuracySec=1s", "--service-type=oneshot",
            "--property=User=root", "--property=Group=root", "--property=UMask=0077",
            "--property=Restart=no", "--property=MemoryMax=1G", "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%", "--property=TasksMax=256", "--property=TimeoutStartSec=120",
            "--property=TimeoutStopSec=15", "--property=PrivateNetwork=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
            "--property=PrivateTmp=yes", "--property=NoNewPrivileges=yes",
            "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
            "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
            f"--unit={GUARD_SERVICE.removesuffix('.service')}", f"--timer-property=Requisite={UNIT}",
            f"--timer-property=After={UNIT}", f"--timer-property=StopPropagatedFrom={UNIT}",
            f"--property=ReadWritePaths={guard_root}", f"--property=StandardOutput=append:{OPS}/guard.stdout",
            f"--property=StandardError=append:{OPS}/guard.stderr", str(GUARD), str(plan),
            "--plan-sha256", digest, "--self-sha256", GUARD_SHA]


def validate_guard(plan, plan_sha, sample, pid):
    actor = sample["producer"]
    observed = sample["root_physical_observation"]
    cap = plan["maximum_root_physical_bytes"]
    iid = plan["invocation_id"]
    floor = plan["minimum_free_bytes"]
    need(plan == guard_plan(iid, floor, cap - DIAGNOSTIC_GROWTH) and fingerprint(plan_sha),
         "foreign guard plan")
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and sample["producer_invocation_id"] == actor["invocation_id"] == iid
         and actor["pid"] == pid > 1 and actor["active"] == "active" and actor["sub"] == "running"
         and actor["cgroup"] == CGROUP and actor["restarts"] == 0
         and fingerprint(sample["guard_invocation_id"], 32)
         and sample["guard_sha256"] == GUARD_SHA and sample["plan_sha256"] == plan_sha,
         "wrong native guard or actor")
    need(sample["maximum_worker_vmas"] == VMA_LIMIT
         and sample["minimum_free_bytes"] == floor <= sample["available_bytes"]
         and sample["maximum_root_physical_bytes"] == cap == observed["maximum_physical_bytes"]
         and 0 < observed["conservative_physical_bytes"] <= cap and observed["exceeds_budget"] is False
         and sample["producer_stop_enabled"] is True and sample["workers"] == []
         and all(sample[field] is None for field in
                 ("trip_reason", "worker_observation_error", "root_physical_observation_error", "bounded_canary", "native_main"))
         and all(sample[field] is False for field in ("bounded_measurement", "r2_mutations", "remote_mutations")),
         "guard has a trip, missing protection, or incorrect resource accounting")


def command():
    return [str(ALIAS / "jetstreamer-node"), "170", str(LEDGER), "--verify",
            f"--epoch-hashes={ALIAS}/canonical-hashes.txt", f"--snapshot-archive={SNAPSHOT}",
            f"--horizon-output={ARCHIVE}", f"--replay-scratch={RUN}/scratch", f"--qualification-end-slot={TERMINAL}"]


def environment(iid):
    return dict(PATH="/usr/bin:/bin", HOME=str(HOME), LANG="C.UTF-8", INVOCATION_ID=iid,
                TMPDIR=str(RUN / "tmp"), JETSTREAMER_PRIVATE_RUN_ROOT=str(RUN / "private"),
                JETSTREAMER_HISTORICAL_WORKER_V1_5_6=str(ALIAS / "historical-worker-v1-5-6"),
                JETSTREAMER_ALLOW_CANDIDATE_RUNTIME="1", SOLANA_RAYON_THREADS="3", RAYON_NUM_THREADS="3",
                JETSTREAMER_HISTORICAL_POH_THREADS="3", JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS="600",
                JETSTREAMER_ARCHIVE_BACKEND="http", JETSTREAMER_HTTP_BASE_URL="https://files.old-faithful.net/",
                JETSTREAMER_COMPACT_INDEX_BASE_URL="https://files.old-faithful.net/",
                JETSTREAMER_NETWORK_CAPACITY_MB="1024", JETSTREAMER_THREADS="12", JETSTREAMER_RIPGET_THREADS="12",
                JETSTREAMER_VERIFY_SNAPSHOTS="1", JETSTREAMER_SKIP_SNAPSHOT_VERIFY="0",
                JETSTREAMER_LOAD_FROM_DIR="0", JETSTREAMER_ENFORCE_ARCHIVE_HASH="1",
                JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS="0",
                RUST_LOG="info,solana_metrics=off,solana_runtime::bank=warn,solana_runtime::accounts_db=warn")


def service(inputs, digest):
    gate_plan(inputs)
    need(fingerprint(digest), "invalid input plan SHA-256")
    indexes = "".join(f"BindReadOnlyPaths={row['path']}:{LEDGER}/compact-indexes/170/{Path(row['path']).name}\n"
                      for row in inputs["indexes"])
    return f"""[Unit]
Description=Guarded epoch 170 metered hourly diagnostic
[Service]
Type=exec
User=sol
Group=horizon
WorkingDirectory={LEDGER}
Restart=no
KillMode=control-group
TimeoutStopSec=2min
CPUQuota=300%
MemoryHigh={ACTOR_MEMORY_HIGH}
MemoryMax={ACTOR_MEMORY}
MemorySwapMax=0
TasksMax=1024
LimitNOFILE=1048576
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=4
OOMPolicy=stop
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777,size=64M
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=cgroup
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
InaccessiblePaths=-/home/sol/.config -/home/sol/.ssh -/home/sol/.gnupg -/home/sol/.codex -/home/sol/workspace
NoExecPaths=/home/sol
ExecPaths={RUN} {ALIAS}/jetstreamer-node {ALIAS}/historical-worker-v1-5-6
ReadWritePaths={RUN}
BindReadOnlyPaths={OPS}/sealed/diagnostic170.py:{ALIAS}/diagnostic170.py
BindReadOnlyPaths={OPS}/sealed/canonical-hashes.txt:{ALIAS}/canonical-hashes.txt
BindReadOnlyPaths={OPS}/sealed/inputs.json:{ALIAS}/inputs.json
BindReadOnlyPaths={OPS}/barrier:{ALIAS}/barrier
BindReadOnlyPaths={NODE}:{ALIAS}/jetstreamer-node
BindReadOnlyPaths={WORKER}:{ALIAS}/historical-worker-v1-5-6
BindReadOnlyPaths={SNAPSHOT}:{SNAPSHOT}
BindReadOnlyPaths={GENESIS}:{LEDGER}/genesis.tar.bz2
{indexes}StandardOutput=append:{RUN}/producer.log
StandardError=append:{RUN}/producer.log
ExecStart=/usr/bin/python3 -IB {ALIAS}/diagnostic170.py run {digest}
"""


def validate_grant(grant, inputs_sha, iid, pid, ticks, boot, now):
    need(grant["schema"] == GRANT_SCHEMA and grant["unit"] == UNIT and fingerprint(iid, 32)
         and grant["invocation_id"] == iid and grant["pid"] == pid > 1 and grant["start_ticks"] == ticks
         and grant["boot_id"] == boot and 0 <= now - grant["issued_unix_seconds"] <= 90
         and grant["inputs_sha256"] == inputs_sha, "foreign or expired grant")
    for name in ("native_post_guard_fit_sha256", "guard_plan_sha256", "first_guard_sha256"):
        need(fingerprint(grant[name]), f"missing grant evidence {name}")
    need(grant["archive_publication_authorized"] is False and grant["resource_credit_bytes"] == 0
         and grant["retained_booking_bytes"] == ROOT_BOOKING and grant["private_growth_bytes"] == DIAGNOSTIC_GROWTH
         and len(grant["log_device_inode"]) == 2 and all(type(value) is int and value > 0 for value in grant["log_device_inode"]),
         "wrong grant authority or reservation")


def verify_cgroup(iid):
    need(os.geteuid() == 1001 and os.getegid() == 1003
         and Path("/proc/self/cgroup").read_text().strip() == f"0::{CGROUP}" and fingerprint(iid, 32),
         "wrong producer identity")
    cg = Path("/sys/fs/cgroup") / CGROUP.lstrip("/")
    quota, period = (int(x) for x in (cg / "cpu.max").read_text().split())
    limits = {name: (cg / name).read_text().strip() for name in
              ("memory.max", "memory.high", "memory.swap.max", "pids.max")}
    need(quota == period * 3 and limits == {
        "memory.max": str(ACTOR_MEMORY), "memory.high": str(ACTOR_MEMORY_HIGH),
        "memory.swap.max": "0", "pids.max": "1024"}, "wrong producer resource limits")


def run(inputs_sha):
    iid = os.environ["INVOCATION_ID"]
    verify_cgroup(iid)
    path = ALIAS / "inputs.json"
    inputs = json.loads(pinned(path, inputs_sha, root=True, limit=128 << 10, read_only=True)[1])
    gate_plan(inputs)
    root_shape()
    for executable, digest in (("jetstreamer-node", NODE_SHA), ("historical-worker-v1-5-6", WORKER_SHA)):
        pinned(ALIAS / executable, digest, root=True, read_only=True)
    pinned(LEDGER / "genesis.tar.bz2", GENESIS_SHA, root=True, limit=100_000, read_only=True)
    _, names = stable(ALIAS / "canonical-hashes.txt", root=True, limit=1024, read_only=True)
    need(names == CHECKPOINTS, "wrong canonical checkpoint names")
    for target, original in [(SNAPSHOT, inputs["snapshot"]), *[
        (LEDGER / "compact-indexes/170" / Path(row["path"]).name, row) for row in inputs["indexes"]
    ]]:
        need(target.resolve(strict=True) == target and stat.S_ISREG(target.lstat().st_mode)
             and identity(target.lstat()) == original["identity"] and os.statvfs(target).f_flag & os.ST_RDONLY,
             f"changed read-only bank or index {target}")
    pid = os.getpid()
    ticks = int(Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19])
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    deadline = time.monotonic() + 180
    print(json.dumps(dict(phase="await-first-guard-and-post-fit", invocation_id=iid, pid=pid, start_ticks=ticks)), flush=True)
    while time.monotonic() < deadline:
        try:
            _, raw = stable(ALIAS / "barrier/allow.json", root=True, limit=16 << 10, read_only=True)
            break
        except FileNotFoundError:
            time.sleep(0.2)
    else:
        raise TimeoutError("first protective guard or post-fit release expired")
    grant = json.loads(raw)
    validate_grant(grant, inputs_sha, iid, pid, ticks, boot, time.time())
    need(all(identity(os.fstat(fd))[:2] == grant["log_device_inode"] for fd in (1, 2)),
         "different bound append log")
    print(json.dumps(dict(phase="exec-bounded-metered-node", invocation_id=iid, slot_start=FIRST, slot_end=TERMINAL)), flush=True)
    argv = command()
    os.execve(argv[0], argv, environment(iid))


def validate_manifest(d):
    need((d["schema_version"], d["epoch"], d["output_slot_start"], d["output_slot_count"]) ==
         (1, 170, FIRST, SLOT_COUNT) and d["worker_executable_sha256"] == WORKER_SHA
         and d["runtime"]["runtime_profile"] == "solana-v1.5.6"
         and d["runtime"]["runtime_admission"] == "candidate"
         and d["runtime"]["runtime_revision"] == "01e4d0a1e9917701d1a148e1043b0ccf545c27f1"
         and d["runtime"]["genesis_hash"] == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
         and fingerprint(d["archive_sha256"]), "foreign private segment")
    for field, slot, accounts in (("bootstrap", BOOTSTRAP, START_HASH), ("terminal", TERMINAL, END_HASH)):
        row = d[field]
        need((row["slot"], row["accounts_hash"], row["slot_complete"]) == (slot, accounts, True),
             f"wrong {field} checkpoint")


def validate_log(stream, archive_size, iid):
    events = {tag: [] for tag in ("gate", "feature", "bounded", "terminal", "file", "commit")}
    for n, line in enumerate(iter(lambda: stream.readline((1 << 20) + 1), b"")):
        need(len(line) <= 1 << 20 and line.endswith(b"\n"), "oversized or truncated producer log")
        t = line.decode("utf-8")
        if "historical execution mismatch" in t or "historical signature mismatch" in t:
            raise ValueError(f"execution comparison failed at line {n+1}")
        if t.startswith("{") and '"phase": "exec-bounded-metered-node"' in t:
            need(json.loads(t)["invocation_id"] == iid, "reused producer log")
            events["gate"].append(n)
        if t.rstrip() == f"historical per-byte logging feature at restored bank slot {BOOTSTRAP}: activated_at=Some(66528004)":
            events["feature"].append(n)
        if (f"epoch 170: compatibility segment {FIRST}..{TERMINAL+1} input=Protobuf "
                "missing-status=Reject status-validation=SourceExact "
                "execution=solana-v1.5.6-epochs-158-173-checkpoint-candidate output=HorizonV2") in t:
            events["bounded"].append(n)
        if f"historical checkpoint slot={TERMINAL} bank_hash=" in t and f" accounts_hash={END_HASH} " in t and " complete=true " in t:
            events["terminal"].append(n)
        if f"horizon archive complete: slots={SLOT_COUNT} " in t and f" bytes={archive_size} " in t:
            events["file"].append(n)
        if t.rstrip().endswith(f"published verified historical segment evidence {MANIFEST}"):
            events["commit"].append(n)
    need(all(len(v) == 1 for v in events.values())
         and all(events["gate"][0] < events[k][0] < events["commit"][0] for k in ("feature", "bounded", "terminal", "file")),
         "missing or disordered strict replay/segment log evidence")
    return events


def inspect(grant_path, grant_sha):
    grant = json.loads(pinned(grant_path, grant_sha, root=True, limit=16 << 10)[1])
    iid = grant["invocation_id"]
    boot = grant["boot_id"]
    validate_grant(grant, grant["inputs_sha256"], iid, grant["pid"], grant["start_ticks"],
                   boot, grant["issued_unix_seconds"])
    need(os.geteuid() == 0, "PID1 journal proof requires root custody")
    journal = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-o", "json", "_PID=1",
        f"UNIT={UNIT}", f"_BOOT_ID={boot.replace('-', '')}", f"INVOCATION_ID={iid}"], timeout=20)
    events = [json.loads(line) for line in journal.splitlines()]
    sha_events = {"7ad2d189f7e94e70a38c781354912448", "d9b373ed55a64feb8242e02dbe79a49c",
                  "98e322203f7a4ed290d09fe03c09fe15", "de5b426a63be47a7b6ac3eaac82e2f6f"}
    ends = [e for e in events if e["MESSAGE_ID"] in sha_events]
    need(len(ends) == 1 and ends[0]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
         "no unambiguous successful native terminal")
    need(not Path("/sys/fs/cgroup" + CGROUP).exists(), "producer has not drained")
    proof, raw = stable(MANIFEST, limit=1 << 20)
    manifest = json.loads(raw)
    validate_manifest(manifest)
    arc, _ = pinned(ARCHIVE, manifest["archive_sha256"])
    with ARCHIVE.open("rb") as f:
        need(identity(os.fstat(f.fileno())) == arc["identity"] and f.read(8) == b"JSHZN1\0\0",
             "wrong archive header")
        f.seek(-8, os.SEEK_END)
        need(f.read(8) == b"\0\0NZHSJ1" and identity(ARCHIVE.lstat()) == arc["identity"], "wrong archive footer")
    log = RUN / "producer.log"
    with log.open("rb") as stream:
        before = identity(os.fstat(stream.fileno()))
        need(before[:2] == grant["log_device_inode"], "different append log")
        matches = validate_log(stream, arc["identity"][2], iid)
        need(before == identity(log.lstat()), "changed append log")
    return dict(schema="horizon-epoch170-metered-hourly-result-v1", invocation_id=iid,
                private_diagnostic_passed=True, signed_source_status_verified_by_node=True, case=CASE,
                native_terminal=ends[0], manifest=proof, archive=arc, log_lines=matches,
                native_vm_logs_captured=False, independent_reader_pending=True, canonical_publication_authorized=False)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="action", required=True)
    for action, arguments in (("prepare", ("bootstrap_metadata", "terminal_metadata", "car_segment")),
                              ("service", ("inputs", "sha256")), ("run", ("sha256",)),
                              ("guard-plan", ("invocation_id", "minimum_free_bytes", "baseline_bytes")),
                              ("guard-argv", ("guard_plan", "sha256")),
                              ("guard-check", ("guard_plan", "sha256", "sample", "pid")),
                              ("inspect", ("grant", "sha256")),
                              ("checkpoint-names", ()), ("facts", ())):
        parser = sub.add_parser(action)
        for arg in arguments:
            parser.add_argument(arg, type=int if arg.endswith("_bytes") or arg == "pid" else str)
    args = cli.parse_args()
    if args.action == "prepare":
        value = prepare(Path(args.bootstrap_metadata), Path(args.terminal_metadata), Path(args.car_segment))
    elif args.action == "service":
        value = json.loads(pinned(Path(args.inputs), args.sha256, root=True, limit=128 << 10)[1])
        print(service(value, args.sha256), end="")
        return
    elif args.action == "run":
        run(args.sha256)
        return
    elif args.action == "guard-plan":
        value = guard_plan(args.invocation_id, args.minimum_free_bytes, args.baseline_bytes)
    elif args.action == "guard-argv":
        value = guard_command(Path(args.guard_plan), args.sha256)
    elif args.action == "guard-check":
        plan = json.loads(pinned(Path(args.guard_plan), args.sha256, root=True, limit=16 << 10)[1])
        receipt, raw = stable(Path(args.sample), root=True, immutable=False, limit=128 << 10)
        sample = json.loads(raw)
        validate_guard(plan, args.sha256, sample, args.pid)
        value = dict(sample=receipt, producer_invocation_id=sample["producer_invocation_id"],
                     guard_invocation_id=sample["guard_invocation_id"], observed_bytes=sample["available_bytes"])
    elif args.action == "inspect":
        value = inspect(Path(args.grant), args.sha256)
    elif args.action == "checkpoint-names":
        print(CHECKPOINTS.decode(), end="")
        return
    else:
        value = dict(case=CASE, bootstrap=SNAPSHOT_ROWS[0], terminal=SNAPSHOT_ROWS[1],
                     run=str(RUN), service=UNIT, guard=TIMER, command=command())
    print(canonical(value).decode(), end="")


if __name__ == "__main__":
    main()
