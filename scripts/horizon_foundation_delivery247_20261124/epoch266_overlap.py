"""Prepare the exact epoch 266 private overlap scope without starting its worker."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

EPOCH = 266
FIRST = 114_923_431
LAST = 114_929_697
ATTEMPT = "hourly-overlap-114929697-v1"
UNIT = f"horizon-qualify-{EPOCH}-{ATTEMPT}.service"
GUARD_UNIT = "horizon-266-hourly-overlap-114929697-protective-v1.service"
STATE = Path("/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-runtime-v1")
INPUTS = STATE.with_name("horizon266-hourly-overlap-114929697-inputs-v1")
TOKENS = STATE.with_name("horizon266-hourly-overlap-114929697-tokens-v1")
ROOT = Path("/home/ubuntu/.jetstreamer-private") / f"qualification-{EPOCH}-{ATTEMPT}"
ARTIFACTS = Path("/home/ubuntu/.jetstreamer-private/epoch266-continuation-static.QKKg36mH")
EXACT = Path("/var/lib/jetstreamer/horizon266-hourly-checkpoint-runtime-v1")
BOOT = Path("/var/lib/jetstreamer/horizon266-checkpoint-114923430-stage-v1")
CPU = "32-39"
EXCLUSIVE = frozenset((*range(32, 40), *range(96, 104), 30, 94))
PRODUCER_RAM = 256 << 30
SCRATCH_RAM = 128 << 30
CONTROL_RAM = 1 << 30
GUARD_RAM = 1 << 30
HOME = 16 << 30
RECEIPTS = 256 << 20
FLOOR = 3_770_104_987_645
WORKER_NAME = "jetstreamer-historical-worker-v1-8-11"
NODE = {
    "path": "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node",
    "sha256": "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32",
}
WORKER = {
    "path": f"/var/lib/jetstreamer/horizon266-capped-worker-package-v199-a1/{WORKER_NAME}",
    "sha256": "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220",
}
GUARD = {
    "path": "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard",
    "sha256": "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d",
}
RESTORE = {
    "path": str(EXACT / "completion-v2.json"),
    "sha256": "acc63b4e817648d1a04b83bf371088c038d27b7b98d916290110b80976812e30",
}
JOURNAL = {
    "path": str(EXACT / "native-result.json"),
    "sha256": "780e4fca701f28b0cee5157f975b73240a5a0be1b27584764079e6699076f8e4",
}
SNAPSHOT_NAME = "snapshot-114923430-CerCifViM5MVzUYPWQm4jRk5zt1dHdFciiR7jrzSjyPj.tar.zst"
TERMINAL_NAME = "snapshot-114929697-BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di.tar.zst"
SNAPSHOT = {"path": str(BOOT / "payload" / SNAPSHOT_NAME),
            "sha256": "2eb5ef470f76a742907165d6c72d4e543c513294dc3ca6200fa3d560705fd023"}
STAGE = {"path": str(BOOT / "sealed-input.json"),
         "sha256": "8e9029573fe834d9ed22feb8a2fa7e800bbd33a6ed2f83d2da0e8b28c40ee0b7"}
SOURCES = tuple(
    {"path": str(ARTIFACTS / name), "sha256": digest}
    for name, digest in (
        ("boundary.json", "89e20c0b401a8e99da6717462c51d5ade1cce4d98c8e43650cfdb1a2dda261b2"),
        ("end-114929697-gcs.json", "1403b662c15e1d33b558f77c4f2e7da18b268b005b0ea23d684b57001bb34008"),
    )
)
INDEXES = Path("/var/lib/jetstreamer/horizon266-index-acquire-v1/cache/sealed")
INDEX_265 = "epoch-265-bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu-mainnet-slot-to-cid.index"
INDEX_266 = "epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet"
GENESIS = Path("/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2")
GUARD_TEMPLATE = {
    "schema": "jetstreamer-horizon-standalone-guard-plan-v1", "unit": UNIT,
    "invocation_id": "a" * 32, "filesystem": "/", "minimum_free_bytes": FLOOR,
    "worker_root": str(ROOT), "maximum_worker_vmas": 3500000,
    "maximum_root_physical_bytes": HOME, "receipt_directory": str(STATE / "guard-receipts"),
}
HOOK = "/var/lib/jetstreamer/horizon230-final-tail-tokens-v1/pre-start.sh"
HOOK_SHA = "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0"


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def reference(path, payload):
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}


def read(bound):
    path = Path(bound["path"])
    data = path.read_bytes()
    assert reference(path, data) == bound
    return json.loads(data)


def files():
    work = ROOT / "work"
    output = work / "output"
    scratch = work / "scratch"
    stage_input = ROOT / "input" / SNAPSHOT_NAME
    checkpoint_bytes = (SNAPSHOT_NAME + "\n" + TERMINAL_NAME + "\n").encode()
    checkpoints = reference(INPUTS / "epoch-hashes.txt", checkpoint_bytes)
    guard_bytes = encode(GUARD_TEMPLATE)
    guard_template = reference(STATE / "static-guard-plan.json", guard_bytes)
    readonly_bindings = [
        (Path(SNAPSHOT["path"]), stage_input, SNAPSHOT["sha256"]),
        (GENESIS, output / "genesis.tar.bz2",
         "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"),
        (INDEXES / INDEX_265, output / "compact-indexes" / "265" / INDEX_265,
         "b7728d6947e43869b78118fe46109f8d5670af6d58ad3f0a1e2bc3261bc25f06"),
        (INDEXES / (INDEX_266 + "-slot-to-cid.index"),
         output / "compact-indexes" / "266" / (INDEX_266 + "-slot-to-cid.index"),
         "9be621a54768e2d22aafd0d639bbf7ae546e7e4eb6610c3dbf2723cf06c8a0b6"),
        (INDEXES / (INDEX_266 + "-cid-to-offset-and-size.index"),
         output / "compact-indexes" / "266" / (INDEX_266 + "-cid-to-offset-and-size.index"),
         "41c9792e0c142984a28f8f653f970223c5525d3c22bfef0df01cd3f7150ac915"),
    ]
    archive = output / f"epoch-266-slots-{FIRST}-{LAST}.jet"
    profile = {
        "schema": "foundation-epoch266-hourly-overlap-runtime-profile-v1",
        "epoch": EPOCH, "unit": UNIT, "guard_unit": GUARD_UNIT, "run_root": str(ROOT),
        "node": NODE, "worker": WORKER, "guard": GUARD, "bootstrap": SNAPSHOT,
        "static_guard_plan": guard_template, "restore_receipt": RESTORE,
        "lossless_native_result": JOURNAL, "epoch_hashes": checkpoints,
        "guarded_whole_tree_cap_bytes": HOME, "guard_memory_bytes": GUARD_RAM,
        "scratch_tmpfs_bytes": SCRATCH_RAM, "scratch_tmpfs_inodes": 1048576,
        "non_tmpfs_producer_memory_bytes": PRODUCER_RAM - SCRATCH_RAM,
        "persistent_archive": str(archive), "persistent_segment_manifest": str(archive) + ".segment.json",
        "properties": {
            "Type": "exec", "User": "ubuntu", "Group": "ubuntu", "UMask": "0077",
            "Restart": "no", "KillMode": "control-group", "OOMPolicy": "kill",
            "AllowedCPUs": CPU, "CPUAffinity": CPU, "CPUQuota": "800%", "TasksMax": "512",
            "MemoryMax": str(PRODUCER_RAM), "MemorySwapMax": "0", "RuntimeMaxSec": "7200",
            "TimeoutStartSec": "180", "TimeoutStopSec": "180", "ProtectSystem": "strict",
            "ProtectHome": "read-only", "PrivateTmp": "yes", "ProtectControlGroups": "yes",
            "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
            "LimitCORE": "0", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
            "ReadWritePaths": str(work), "WorkingDirectory": str(ROOT),
            "TemporaryFileSystem": (
                f"{scratch}:rw,size={SCRATCH_RAM},nr_inodes=1048576,mode=0700,uid=1000,gid=1000,"
                "nosuid,nodev,exec,noswap"
            ),
        },
        "environment": {
            "JETSTREAMER_HISTORICAL_WORKER_V1_8_11": WORKER["path"],
            "JETSTREAMER_FORCE_LEGACY_INDEX": "1", "JETSTREAMER_PRIVATE_RUN_ROOT": str(work / "state"),
            "JETSTREAMER_HISTORICAL_POH_THREADS": "8", "SOLANA_RAYON_THREADS": "8",
            "RAYON_NUM_THREADS": "8", "RUST_MIN_STACK": "134217728", "TMPDIR": str(scratch),
            "JETSTREAMER_NETWORK": "mainnet", "JETSTREAMER_VERIFY_SNAPSHOTS": "1",
            "JETSTREAMER_SKIP_SNAPSHOT_VERIFY": "0", "JETSTREAMER_ENFORCE_ARCHIVE_HASH": "1",
            "JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS": "0", "JETSTREAMER_REPLAY_THREADS": "8",
            "TOKIO_WORKER_THREADS": "8", "JETSTREAMER_RIPGET_THREADS": "1", "RUST_LOG": "info",
            "CLOUDSDK_CONFIG": str(scratch / "isolated-empty-gcloud"),
            "CLOUDSDK_CORE_DISABLE_PROMPTS": "1", "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "1",
        },
        "readonly_bindings": [
            {"path": str(source), "destination": str(target), "sha256": digest}
            for source, target, digest in readonly_bindings
        ],
        "argv": [
            NODE["path"], str(EPOCH), str(output), "--verify", f"--snapshot-archive={stage_input}",
            f"--epoch-hashes={checkpoints['path']}", f"--qualification-end-slot={LAST}",
            f"--horizon-output={archive}", f"--replay-scratch={scratch}",
        ],
        "diagnostic_only": True, "predecessor_native_tuple_qualified": False,
        "cursor_normalization_qualified": False, "publication_authorized": False,
    }
    profile_bytes = encode(profile)
    preflight = {
        "schema": "foundation-epoch266-hourly-overlap-preflight-v1",
        "epoch": EPOCH, "first_slot": FIRST, "last_slot": LAST,
        "evidence": [reference(STATE / "profile.json", profile_bytes), NODE, WORKER, GUARD,
                     RESTORE, JOURNAL, STAGE, *SOURCES, checkpoints, guard_template],
        "private_namespace_validated": True, "writable_private_state_validated": True,
        "static_guard_validated": True, "snapshot_sha256_rechecked": True,
        "publication_authorized": False,
    }
    return {
        "profile.json": profile_bytes,
        "preflight.json": encode(preflight),
        "epoch-hashes.txt": checkpoint_bytes,
        "static-guard-plan.json": guard_bytes,
    }


def stable_identity(path):
    info = path.stat()
    assert stat.S_ISREG(info.st_mode) and path.resolve() == path
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def hash_input(bound):
    path = Path(bound["path"])
    metadata = path.stat()
    assert metadata.st_uid == 0 and metadata.st_nlink == 1 and metadata.st_mode & 0o222 == 0
    identity = stable_identity(path)
    with path.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == bound["sha256"]
    assert stable_identity(path) == identity
    return identity


def validate_sources():
    receipt, native = read(RESTORE), read(JOURNAL)
    assert receipt["native_result"] == native and receipt["native_result_journal_bytes"] == JOURNAL
    assert native["slot"] == FIRST - 1 and native["snapshot_generation"] == 1641767192954871
    assert native["capitalization"] == 512823375441850375 and native["snapshot_sha256"] == SNAPSHOT["sha256"]
    assert native["worker_sha256"] == WORKER["sha256"] and native["slot_complete"]
    assert native["initialization_writes"] == native["replay_entries_sent"] == 0
    boundary, terminal = map(read, SOURCES)
    assert boundary["dense_last_observed_write_plus_one"] == 187121877105
    assert boundary["native_initialized_cursor"] == native["initialized_cursor"] == 187129398665
    assert boundary["raw_cursors_match"] is False and boundary["native_predecessor_tuple_qualified"] is False
    assert Path(terminal["name"]).name == TERMINAL_NAME and terminal["generation"] == "1641767198731933"
    assert terminal["size"] == 15514070431 and terminal["crc32c_hash"] == "exIgJw=="
    read(STAGE)


def write_new(path, payload, mode=0o400):
    with path.open("xb") as target:
        target.write(payload)
        os.fchmod(target.fileno(), mode)
        target.flush()
        os.fsync(target.fileno())


# This script runs in the exact producer mount namespace with no replay binary
# and no network. Its single tiny allocation verifies tmpfs and retained output.
NAMESPACE_PROBE = r"""
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
paths = [Path(p) for p in sys.argv[2:]]
scratch = root / 'work/scratch'
output = root / 'work/output'
assert scratch.stat().st_dev != root.stat().st_dev
assert output.stat().st_dev == root.stat().st_dev
mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
scratch_mount, = (row for row in mounts if row[4] == str(scratch))
separator = scratch_mount.index('-')
assert scratch_mount[separator + 1] == 'tmpfs'
assert 'noswap' in scratch_mount[separator + 3].split(',')
cap = os.statvfs(scratch)
assert cap.f_blocks * cap.f_frsize == 128 << 30 and cap.f_files == 1048576
reads = []
for path in paths:
    row, = (row for row in mounts if row[4] == str(path))
    assert 'ro' in row[5].split(',')
    item = path.stat()
    reads.append(f'{item.st_dev}:{item.st_ino}:{item.st_size}')
for directory in (scratch, output, root / 'work/state'):
    probe = directory / '.epoch266-namespace-probe'
    with probe.open('xb') as f:
        f.write(b'probe')
    probe.unlink()
print(json.dumps(reads))
"""


def prepare():
    """Stage only private directories, static inputs and a read-only namespace probe."""
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    validate_sources()
    rendered = files()
    profile = json.loads(rendered["profile.json"])
    binds = profile["readonly_bindings"]
    assert not STATE.exists() and not INPUTS.exists()
    assert not ROOT.exists()
    # Hash sealed inputs on the already authorized local device. Their packages
    # are root-owned and immutable, and admission rechecks exact inode identities.
    identities = [hash_input({"path": b["path"], "sha256": b["sha256"]}) for b in binds]
    for item in (NODE, WORKER, GUARD):
        hash_input(item)
    assert identities[0][2] == 15477812146
    assert hashlib.sha256(Path(HOOK).read_bytes()).hexdigest() == HOOK_SHA
    STATE.mkdir(mode=0o700)
    INPUTS.mkdir(mode=0o755)
    INPUTS.chmod(0o755)
    ROOT.mkdir(mode=0o700)
    os.chown(ROOT, 1000, 1000)
    for relative in ("input", "work", "work/scratch", "work/state", "work/output",
                     "work/output/compact-indexes", "work/output/compact-indexes/265", "work/output/compact-indexes/266"):
        path = ROOT / relative
        path.mkdir(mode=0o700)
        os.chown(path, 1000, 1000)
    for row in binds:
        write_new(Path(row["destination"]), b"", 0o444)
    for name in ("static-guard-plan.json", "profile.json"):
        write_new(STATE / name, rendered[name])
    write_new(INPUTS / "epoch-hashes.txt", rendered["epoch-hashes.txt"], 0o444)
    guard_ref = profile["static_guard_plan"]
    result = json.loads(subprocess.check_output([
        GUARD["path"], guard_ref["path"], "--plan-sha256", guard_ref["sha256"],
        "--self-sha256", GUARD["sha256"], "--validate-plan-only",
    ], timeout=30))
    assert result["validated"] and result["plan_sha256"] == guard_ref["sha256"]
    write_new(STATE / "static-guard-validation.json", encode(result))
    props = {key: profile["properties"][key] for key in (
        "User", "Group", "ProtectSystem", "ProtectHome", "PrivateTmp", "ReadWritePaths", "TemporaryFileSystem",
    )}
    props.update(PrivateNetwork="yes", MemoryMax="1073741824", MemorySwapMax="0",
                 AllowedCPUs="30", CPUQuota="100%", RuntimeMaxSec="30")
    props["BindReadOnlyPaths"] = " ".join(f'{b["path"]}:{b["destination"]}' for b in binds)
    observed = json.loads(subprocess.check_output([
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        "--unit=foundation-266-overlap-namespace-probe-v1",
        *(f"--property={key}={value}" for key, value in props.items()),
        "/usr/bin/python3", "-B", "-c", NAMESPACE_PROBE, str(ROOT), *(b["destination"] for b in binds),
    ], timeout=35))
    assert observed == [f"{dev}:{ino}:{size}" for dev, ino, size, _, _ in identities]
    assert all(stable_identity(Path(row["path"])) == identity for row, identity in zip(binds, identities, strict=True))
    assert all(Path(row["destination"]).stat().st_size == 0 for row in binds)
    profile_ref = reference(STATE / "profile.json", rendered["profile.json"])
    write_new(STATE / "namespace.json", encode({
        "profile": profile_ref, "mounted_device_inode_size": observed, "host_guard_sees_empty_placeholders": True,
        "tmpfs_private_to_producer_and_noswap": True, "binds_read_only": True,
        "persistent_output_on_home": True, "historical_worker_executed": False,
        "source_identities": identities,
    }))
    dev, ino, size, mtime, ctime = identities[0]
    write_new(STATE / "bootstrap-recheck.json", encode({
        "bootstrap": dict(SNAPSHOT, identity=f"{dev}:{ino}:{size}:{mtime // 10**9}:{ctime // 10**9}",
                          mtime_ns=mtime, ctime_ns=ctime),
        "sha256_rechecked": True, "generation": 1641767192954871,
        "stage": STAGE, "native_result": JOURNAL,
    }))
    write_new(STATE / "preflight.json", rendered["preflight.json"])
    return reference(STATE / "preflight.json", rendered["preflight.json"])


if __name__ == "__main__":
    assert __debug__ and len(sys.argv) == 2
    mode = sys.argv[1]
    if mode == "--bindings":
        print(json.dumps({name: reference((INPUTS if name == "epoch-hashes.txt" else STATE) / name, payload)
                          for name, payload in files().items()}, indent=2))
    elif mode == "--prepare":
        assert os.environ.get("CODEX_THREAD_ID")
        repo = "/home/ubuntu/workspace/jetstreamer"
        source = f"scripts/horizon_foundation_delivery247_20261124/{Path(__file__).name}"
        assert Path(__file__).read_bytes() == subprocess.check_output(
            ["runuser", "-u", "ubuntu", "--", "git", "-C", repo, "show", f"origin/account-updates:{source}"],
            timeout=15,
        )
        print(json.dumps(prepare(), indent=2))
    else:
        raise SystemExit("expected --bindings or --prepare")
