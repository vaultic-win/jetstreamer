#!/usr/bin/python3
"""Prepare and admit the private checkpoint-bounded epoch 167 diagnostic."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

HOME = Path("/home/sol")
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch167-checkpoint-bounded-20261127-v1"
PACKAGE = ROOT / "package"
CAPACITY_DEPLOYMENT = RT / "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-independent-v20-joint168-v31-bounded167"
LANE = HOME / ".jetstreamer-private/epoch167-standard-lane-20261109-v1"
RUN = LANE / "checkpoint-inputs-20261127-v1/bounded-72509256-72515090-v1"
OUTPUT = RUN / "output"
PRIVATE = RUN / "private"
LOG = RUN / "producer.log"
ARCHIVE = OUTPUT / "epoch-167-checkpoint-bounded.jet"
ALIAS = Path("/run/horizon-bounded167-checkpoints-v1")
UNIT = "horizon-qualify-167-checkpoint-bounded-20261127-v1.service"
TIMER = "horizon-guard-167-checkpoint-bounded-20261127-v1.timer"
GUARD_SERVICE = TIMER.replace(".timer", ".service")
CGROUP = f"/system.slice/{UNIT}"
KERNEL = Path("/sys/fs/cgroup")
OLD = "horizon-qualify-167-source-index-v3-20261122.service"
START, END = 72509256, 72515090
BOOTSTRAP = "snapshot-72509256-5QgiqJPdQHGW8XPQofearvgZVmesY99YLHr1n7gVCkBD.tar.zst"
BOOTSTRAP_SHA = "e35c2d247099b5f2edace0d09485fd254f852069681fa09cf39168dbe42c5769"
END_SNAPSHOT = "snapshot-72515090-DWgHoJPPD1XaWGLpasfR4RVnAU1CBoKUrjCgtoCfEDPK.tar.zst"
CHECKPOINTS = f"{BOOTSTRAP}\n{END_SNAPSHOT}\n".encode()
GENESIS_SHA = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
GIB = 1 << 30
CAP, MEMORY, MEMORY_HIGH, GUARD_MEMORY = 512 * GIB, 44 * GIB, 42 * GIB, GIB
CPU, GUARD_CPU = 3_000_000, 250_000
MAX_VMAS = 3_500_000
ORIGINAL_FLOOR = 8_594_041_336_400
MAX_AGE = 120
GUARD = ROOT / "guard-tools/guard"
WORKER_DIR = RT / "epoch167-source-index-rebook-20261122-v3/checkpoint-trace-20261127-v1"
WORKER_SHA = "07b09d779706a789c668681ad9685e9ad62290a6930667c5f74a099a516d28cc"
WORKER_COMMIT = "f6f69d9de59fe31c06ccd11e457e43b12d4e8551"
GUARD_SHA = "2448b9818aae5265f842d0a2264fad22515dd4eb5902befd335fca986eba1881"
GUARD_SEAL_SHA = "475786f3041787d2fbeb544f7f85a2e81dd26fbfc0d74ecc43e09ce27f1de011"
GUARD_COMMIT = "fe40ca2bbaec1720d6c1e6bac7457b049fad5b72"
TERMINAL = {
    "path": str(RT / "epoch167-source-index-rebook-20261122-v3/EXECUTION_TERMINAL_20261127.json"),
    "sha256": "0e441ccfef45d40f2d707f6136bb76c0e4bd3b2a21bfebff9641f761dd8a27e2",
}
OVERLAP = {
    "path": str(RT / "epoch167-source-index-rebook-20261122-v3/RETAINED_OVERLAP_VERIFIED_20261127.json"),
    "sha256": "38dd9f69f4eacf3b619fcb6a1ff36d07c88ffa7c80cbf0514a52f688ec96d84d",
}
V31_SEAL = {
    "path": str(RT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v31-entry146/deployment-seal-receipt.json"),
    "sha256": "fce9080d3190e16d9353a594113d9ebb785d7f0be6f22c9e5c56f31e40f3240e",
}
V31_ACTIVE = {
    "path": str(RT / "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V31_ACTIVE.json"),
    "sha256": "e1656e850ee59398d8d5489b39d81a023744dc1d37132f632592feb52c54f2f5",
}
PEER146 = "horizon-qualify-146-full-local-20261126-v1.service"
PEER168 = "horizon-qualify-168-joint-checkpoint-reduced-20261126-v1.service"
PEER172 = "horizon-qualify-172-full-half-core-20261120-v1.service"
HEX = re.compile("[a-f0-9]{64}")
IID = re.compile("[a-f0-9]{32}")
TOKEN = re.compile(r"[A-Za-z0-9_.:/-]+")
FLAGS = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def need(condition, message):
    if not condition:
        raise ValueError(message)


def ref(path, sha256):
    path = Path(path)
    need(path.is_absolute() and TOKEN.fullmatch(str(path)) and HEX.fullmatch(sha256), "invalid evidence reference")
    return {"path": str(path), "sha256": sha256}


def encode(row):
    return (json.dumps(row, sort_keys=True, indent=2) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(meta):
    return [meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns]


def file_identity(path, sha=None, *, trusted=False, mounted=False, executable=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and TOKEN.fullmatch(str(path)),
         f"indirect file {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | FLAGS), "rb") as source:
        st = os.fstat(source.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size > 0
             and (not trusted or st.st_uid == st.st_gid == 0 and not st.st_mode & 0o222)
             and (not executable or st.st_mode & 0o111)
             and (not mounted or os.fstatvfs(source.fileno()).f_flag & os.ST_RDONLY),
             f"wrong custody for {path}")
        if sha is not None:
            need(HEX.fullmatch(sha) and hashlib.file_digest(source, "sha256").hexdigest() == sha,
                 f"wrong digest for {path}")
        sealed = identity(st)
        need(identity(os.fstat(source.fileno())) == identity(path.lstat()) == sealed,
             f"file changed during inspection {path}")
        return sealed


def read(reference):
    path = Path(ref(**reference)["path"])
    with os.fdopen(os.open(path, os.O_RDONLY | FLAGS), "rb") as handle:
        st = os.fstat(handle.fileno())
        need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode)
             and st.st_uid == st.st_gid == 0 and st.st_nlink == 1
             and not st.st_mode & 0o022 and 0 < st.st_size <= 32 * 1024**2,
             f"unsealed evidence {path}")
        data = handle.read(st.st_size + 1)
        need(len(data) == st.st_size and digest(data) == reference["sha256"]
             and identity(os.fstat(handle.fileno())) == identity(path.lstat()) == identity(st),
             f"changed evidence {path}")
    return json.loads(data)


def bind_file(reference, *, executable=False):
    path = Path(ref(**reference)["path"])
    return dict(reference, identity=file_identity(path, reference["sha256"], executable=executable))


def present_member(seal_ref, name, *, executable=False):
    seal = read(seal_ref)
    root = Path(seal["destination"])
    need(Path(seal_ref["path"]) == root / "deployment-seal-receipt.json"
         and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
         and all(seal.get(key) is False for key in
                 ("publication_authorized", "replay_launch_authorized", "r2_mutations", "remote_mutations")),
         "wrong package seal")
    member, = (row for row in seal["members"] if row["name"] == name)
    item = ref(root / name, member["sha256"])
    file_identity(item["path"], item["sha256"], trusted=True, executable=executable)
    return item


def atomic(path, data, mode=0o400):
    need(path.is_absolute() and TOKEN.fullmatch(str(path)), f"invalid output path: {path}")
    need(not path.exists() and not path.is_symlink(), f"output exists: {path}")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        tmp = f".pending-{os.getpid()}-{path.name}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.link(tmp, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        finally:
            os.unlink(tmp, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    return ref(path, digest(data))


def command(args, *, timeout=15):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout).stdout


def props(unit, keys):
    # systemctl returns 4 and still prints native not-found status for a fresh unit.
    argv = ["/usr/bin/systemctl", "show", "--no-pager", "--property", ",".join(keys), "--", unit]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, text=True)
    row = dict(line.split("=", 1) for line in result.stdout.splitlines())
    need(result.returncode == 0 or result.returncode == 4 and row.get("LoadState") == "not-found",
         f"systemd census failed for {unit}: {result.stderr.strip()}")
    need(row.get("Id") == unit and all(key in row for key in keys), f"missing PID1 properties of {unit}")
    return row


STATE = ("Id", "LoadState", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlPID", "ControlGroup", "Job")


def idle(unit, states=("inactive", "failed")):
    row = props(unit, STATE)
    need(row["ActiveState"] in states and row["MainPID"] == row["ControlPID"] == "0"
         and not row["ControlGroup"] and not row["Job"]
         and not (KERNEL/"system.slice"/unit).exists(), f"occupied unit: {unit}")


def permit_exists():
    return (ROOT/"barrier/allow").exists() or (ROOT/"barrier/allow").is_symlink()


def guard_floor(pod, quote):
    return max(ORIGINAL_FLOOR, pod["protected_raw_floor_bytes"],
               quote["full146"]["pending_guard"]["minimum_free_bytes"], quote["joint168"]["guard_floor_bytes"],
               pod["retained_167"]["guard_floor_bytes"], pod["retained_170"]["guard_floor_bytes"],
               pod["active168_guard_floor"], pod["candidate136"].get("guard_floor", 0),
               *(row["guard"]["floor"] for row in pod["survivors"].values()),
               *(row["floor"] for row in pod["replacements"].values()))


def funding(current, zero, absolute, remaining, donor, available, armed=None, unmeasured=0):
    need(0 < zero <= current and 0 < absolute <= current and 0 < remaining <= CAP
         and 0 <= unmeasured <= remaining, "invalid combined HOME projection")
    floor = max(absolute, zero, current - remaining + unmeasured)
    need(armed is None or armed >= floor, f"armed floor short by {floor - (armed or 0)} bytes")
    floor = floor if armed is None else armed
    required = floor + remaining
    need(required <= available, f"epoch 167 HOME shortfall {required-available} bytes")
    need(required - (current + unmeasured) <= donor,
         f"epoch 167 donor headroom shortfall {required-current-unmeasured-donor} bytes")
    return floor, required


def cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, help="save the result atomically in a private root-owned directory")
    sub = parser.add_subparsers(dest="operation", required=True)
    for stage in ("prepare", "prestart", "argv", "owner", "held", "guard-plan", "guard-argv", "first-guard",
                  "post-guard", "release"):
        item = sub.add_parser(stage)
        for name in {
            "prepare": ("spec", "sha256", "output_dir"),
            "prestart": ("prepared", "sha256", "package_seal_sha256", "request", "request_sha256"),
            "argv": ("intent", "sha256"),
            "owner": ("intent", "sha256"),
            "held": ("intent", "sha256"),
            "guard-plan": ("intent", "sha256", "held", "held_sha256"),
            "guard-argv": ("plan", "sha256"),
            "first-guard": ("intent", "sha256", "plan", "plan_sha256", "sample", "sample_sha256"),
            "post-guard": ("intent", "sha256", "first_guard", "first_guard_sha256"),
            "release": ("intent", "sha256", "post_guard", "post_guard_sha256"),
        }[stage]:
            item.add_argument(name)
    return parser.parse_args()

NODE_DIR = RT / "epoch167-local-index-successor-20261121-v1/deployment"
INDEX_DIR = HOME / ".jetstreamer-private/public-method-20261120/167-source-index/qualified-v1"
NODE = ref(NODE_DIR/"jetstreamer-node", "6b0f3089c1c1108dbbbea76a06625d3b285de647f83b50791ead121e1af81699")
GENESIS = ref("/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1/genesis.tar.bz2", GENESIS_SHA)
INDEX_MANIFEST = ref(INDEX_DIR/"manifest.json", "8d0bb4e330a3d6d9c3c014e63df99069856af6298de43a319ef710021b88a7b2")
RAW_INDEX = ref(INDEX_DIR/"epoch-167-slot-ranges.raw", "379692ca3092bcbdd29c968606dc72cf6703a7e41a8c4a774ee4540ba51d9cf7")
CHECKPOINT_ROWS = (
    ("mainnet-beta-ledger-europe-fr2", "nearest_before", 72143812, BOOTSTRAP,
     "1634787089886637", "2051599831", "t6bEhA==", "Yse8Pil4BqKF62vKCr0SxA=="),
    ("mainnet-beta-ledger-us-ny5", "nearest_after", 72143703, END_SNAPSHOT,
     "1634787383763977", "2007810278", "QyW/Qw==", "j3tvPd6btd8Y5dPNkBFvUA=="),
)


def checkpoint_evidence(document):
    for bucket, selection, anchor, filename, generation, size, crc, md5 in CHECKPOINT_ROWS:
        row = document["regions"][bucket][selection]
        expected = dict(bucket=bucket, name=f"{anchor}/hourly/{filename}", generation=generation,
                        size=size, crc32c=crc, md5Hash=md5)
        need(all(row[key] == value == row["independently_authenticated_generation_get"][key]
                 for key, value in expected.items()),
             f"different generation-pinned checkpoint: {filename}")


def child(path, uid, gid, mode):
    meta = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(meta.st_mode)
         and (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) == (uid, gid, mode),
         f"wrong exact directory {path}")
    return meta


def immutable(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | FLAGS)
    try:
        flags = int.from_bytes(fcntl.ioctl(fd, 0x80086601, bytes(8)), "little")
        return bool(flags & 0x10)
    finally:
        os.close(fd)


def run_directories():
    base = child(RUN, 1001, 1003, 0o700)
    need(immutable(RUN), "seal the run parent before admission")
    for path in (OUTPUT, PRIVATE):
        meta = child(path, 1001, 1003, 0o700)
        need(meta.st_dev == base.st_dev and not immutable(path), f"wrong writable run child {path}")
    need(base.st_dev == HOME.stat().st_dev, "epoch 167 must use the HOME filesystem")


def gate_environment():
    return {
        "HOME": str(HOME), "USER": "sol", "LOGNAME": "sol", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin",
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME": "1",
        "JETSTREAMER_HISTORICAL_WORKER_V1_5_6": str(ALIAS/"jetstreamer-historical-worker-v1-5-6"),
        "JETSTREAMER_HISTORICAL_TRACE_EPOCH167": "1",
        "JETSTREAMER_HISTORICAL_POH_THREADS": "2", "SOLANA_RAYON_THREADS": "2", "RAYON_NUM_THREADS": "2",
        "JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS": "600",
        "JETSTREAMER_ARCHIVE_BACKEND": "http", "JETSTREAMER_HTTP_BASE_URL": "https://files.old-faithful.net/",
        "JETSTREAMER_COMPACT_INDEX_BASE_URL": "https://files.old-faithful.net/",
        "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST": INDEX_MANIFEST["path"],
        "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256": INDEX_MANIFEST["sha256"],
        "JETSTREAMER_NETWORK_CAPACITY_MB": "1024", "JETSTREAMER_THREADS": "4", "JETSTREAMER_RIPGET_THREADS": "4",
        "JETSTREAMER_CLEAR_ACCOUNTS_ON_START": "true", "JETSTREAMER_VERIFY_SNAPSHOTS": "1",
        "JETSTREAMER_SKIP_SNAPSHOT_VERIFY": "0", "JETSTREAMER_LOAD_FROM_DIR": "0",
        "JETSTREAMER_ENFORCE_ARCHIVE_HASH": "1", "JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS": "0",
        "JETSTREAMER_PRIVATE_RUN_ROOT": str(PRIVATE),
        "RUST_LOG": "info,solana_metrics=off,solana_runtime::bank=warn,solana_runtime::accounts_db=warn",
        "RUST_BACKTRACE": "1",
    }


def node_argv():
    return [str(ALIAS/"jetstreamer-node"), "167", str(OUTPUT), "--verify",
            f"--qualification-end-slot={END}", f"--snapshot-archive={ALIAS/BOOTSTRAP}",
            f"--epoch-hashes={ALIAS/'epoch-hashes.txt'}", f"--horizon-output={ARCHIVE}"]


def placement(worker):
    return [
        (ALIAS/"jetstreamer-node", NODE, True),
        (ALIAS/"jetstreamer-historical-worker-v1-5-6", worker, True),
        (ALIAS/BOOTSTRAP, ref(RUN.parent/BOOTSTRAP, BOOTSTRAP_SHA), False),
        (OUTPUT/"genesis.tar.bz2", GENESIS, False),
        (Path(INDEX_MANIFEST["path"]), INDEX_MANIFEST, False),
        (Path(RAW_INDEX["path"]), RAW_INDEX, False),
    ]


def remote_contains(commit):
    repo = HOME/"workspace/jetstreamer"
    command(["/usr/bin/git", "-c", f"safe.directory={repo}", "-C", str(repo),
             "merge-base", "--is-ancestor", commit, "refs/remotes/origin/account-updates"])


def guard_binary():
    seal = ref(GUARD.parent/"deployment-seal-receipt.json", GUARD_SEAL_SHA)
    binary = present_member(seal, "guard", executable=True)
    build = read(present_member(seal, "build.json"))
    need(binary == ref(GUARD, GUARD_SHA) and build["binary"]["sha256"] == GUARD_SHA
         and build["commit"] == GUARD_COMMIT, "different bounded 167 guard build")
    remote_contains(GUARD_COMMIT)
    return binary


def worker_member(spec):
    seal = ref(WORKER_DIR/"deployment-seal-receipt.json",
               "a8473327dfc475712274b5bae1e058b498f87f55993a79f90fa01668dbda84e6")
    need(spec["worker_deployment"] == seal, "different signed-trace worker seal")
    worker = present_member(seal, "jetstreamer-historical-worker-v1-5-6", executable=True)
    build = read(present_member(seal, "WORKER_BUILD.json"))
    need(worker == ref(WORKER_DIR/"jetstreamer-historical-worker-v1-5-6", WORKER_SHA)
         and build["schema"] == "horizon-167-trace-worker-build-v1"
         and build["product"]["sha256"] == WORKER_SHA and build["source_commit"] == WORKER_COMMIT
         and build["feature_cfgs"] == ["historical-per-byte-logging"]
         and build["pid1_success"]["_PID"] == "1"
         and "48 passed; 0 failed" in build["test_result"]["MESSAGE"],
         "signed-trace worker build authority is incomplete")
    remote_contains(WORKER_COMMIT)
    return worker


def verify_payload(row):
    need(row["schema"] == "horizon-epoch167-bounded-replay-payload-v1" and row["epoch"] == 167
         and row["terminal"] == TERMINAL and row["overlap"] == OVERLAP and row["range"] == [START, END] and row["argv"] == node_argv()
         and row["environment"] == gate_environment() and row["guard_cap"] == CAP
         and row["worker"] == ref(WORKER_DIR/"jetstreamer-historical-worker-v1-5-6", WORKER_SHA)
         and row["guard"] == ref(GUARD, GUARD_SHA)
         and row["producer_unit"] == UNIT and row["archive_publication_authorized"] is False,
         "wrong bounded route")
    want = placement(row["worker"])
    need(len(row["files"]) == len(want) and len({item["target"] for item in row["files"]}) == len(want),
         "unexpected bounded input projection")
    for item, (target, source, executable) in zip(row["files"], want):
        need(item["target"] == str(target) and item["source"]["path"] == source["path"]
             and item["source"]["sha256"] == source["sha256"] and item["executable"] is executable
             and len(item["source"]["identity"]) == 5, "wrong bounded input projection")


def prepare(spec_ref, output):
    spec = read(spec_ref)
    need(spec["schema"] == "horizon-epoch167-bounded-replay-spec-v1"
         and spec["terminal"] == TERMINAL, "wrong epoch 167 build specification")
    checkpoint_evidence(read(spec["checkpoint_generations"]))
    source = read(spec["closed_input_digests"])
    need(source["schema"] == "horizon-167-closed-input-digests-v1" and source["terminal"] == TERMINAL
         and source["bootstrap"]["sha256"] == BOOTSTRAP_SHA and source["physical_end_exclusive"] == 72512768
         and source["archive_finalized"] is False and source["payload_semantics_verified"] is False,
         "wrong original retained inputs")
    overlap = read(OVERLAP)
    need(overlap["schema"] == "horizon-167-retained-checkpoint-window-v1"
         and overlap["source_digest"] == spec["closed_input_digests"]
         and overlap["source_window"]["first_slot"] == str(START)
         and overlap["source_window"]["last_slot"] == "72512767"
         and overlap["first_generation"] == 1634787089886637
         and overlap["publication_authorized"] is False and overlap["complete_prefix_verified"] is False,
         "wrong retained checkpoint overlap")
    worker = worker_member(spec)
    guard = guard_binary()

    files = [dict(target=str(target), source=bind_file(source_ref, executable=executable),
                  executable=executable) for target, source_ref, executable in placement(worker)]
    boot = files[2]["source"]["identity"]
    need(source["bootstrap"]["path"] == files[2]["source"]["path"]
         and [source["bootstrap"][key] for key in ("device", "inode", "length", "mtime_ns")] == boot[:4],
         "FR2 custody changed after digest")
    payload = dict(schema="horizon-epoch167-bounded-replay-payload-v1", epoch=167, range=[START, END],
                   terminal=TERMINAL, overlap=OVERLAP, spec=spec_ref, worker=worker, files=files, argv=node_argv(),
                   environment=gate_environment(), guard_cap=CAP, guard=guard, producer_unit=UNIT,
                   archive_publication_authorized=False)
    verify_payload(payload)
    child(output, 0, 0, 0o700)
    payload_ref = atomic(output/"payload.json", encode(payload), 0o444)
    checkpoints = atomic(output/"epoch-hashes.txt", CHECKPOINTS, 0o444)
    source_path = Path(__file__).resolve()
    source_sha = digest(source_path.read_bytes())
    inputs = [(payload_ref, 0o444), (checkpoints, 0o444), (ref(source_path, source_sha), 0o555)]
    plan = dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(PACKAGE),
                members=[dict(name=Path(item["path"]).name, source=item["path"],
                              sha256=item["sha256"], mode=mode) for item, mode in inputs])
    return dict(schema="horizon-epoch167-bounded-prepared-v1", payload=payload_ref, spec=spec_ref,
                seal_plan=atomic(output/"PACKAGE_PLAN.json", encode(plan)),
                gate_source_sha256=source_sha, checkpoints=checkpoints)


def fresh_outputs():
    for name in (ARCHIVE, Path(str(ARCHIVE)+".segment.json"), Path(str(ARCHIVE)+".sha256")):
        need(not name.exists() and not name.is_symlink(), f"bounded output already exists: {name}")


def projected(row):
    verify_payload(row)
    for item in row["files"]:
        identity_now = file_identity(item["target"], mounted=True, executable=item["executable"])
        need(identity_now == item["source"]["identity"], f"wrong projected inode: {item['target']}")
    file_identity(ALIAS/"epoch-hashes.txt", digest(CHECKPOINTS), trusted=True, mounted=True)
    run_directories()
    mounts = set()
    for path in (RUN, OUTPUT, PRIVATE):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | FLAGS)
        try:
            row, = (row.split()[1] for row in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
                    if row.startswith("mnt_id:"))
            mounts.add(row)
            need(not os.fstatvfs(fd).f_flag & os.ST_RDONLY, f"read-only output child {path}")
        finally:
            os.close(fd)
    need(len(mounts) == 1, "output and scratch must share one writable mount")
    fresh_outputs()


def ticks(pid):
    return int((Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split())[19])


def limits(group):
    quota, period = (int(value) for value in (group/"cpu.max").read_text().split())
    need(quota * 1_000_000 == period * CPU
         and (group/"memory.max").read_text().strip() == str(MEMORY)
         and (group/"memory.high").read_text().strip() == str(MEMORY_HIGH)
         and (group/"memory.swap.max").read_text().strip() == "0"
         and (group/"pids.max").read_text().strip() == "1024", "native producer meter differs")


def match_permit(path, iid):
    try:
        fd = os.open(path, os.O_RDONLY | FLAGS)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        need(stat.S_ISREG(st.st_mode) and (st.st_uid, st.st_gid) == (0, 0)
             and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o444
             and st.st_size == 32 and handle.read(33) == iid.encode()
             and os.fstatvfs(handle.fileno()).f_flag & os.ST_RDONLY, "foreign bounded permit")
    return True


def gate():
    iid = os.environ["INVOCATION_ID"]
    need(os.geteuid() == 1001 and os.getegid() == 1003 and IID.fullmatch(iid) and int(iid, 16)
         and Path("/proc/self/cgroup").read_text().strip() == f"0::{CGROUP}", "different gate actor")
    limits(KERNEL / CGROUP.lstrip("/"))
    payload_sha = os.environ["HORIZON167_PAYLOAD_SHA256"]
    path = ALIAS/"payload.json"
    file_identity(path, payload_sha, trusted=True, mounted=True)
    payload = read(ref(path, payload_sha))
    projected(payload)
    need(all(os.environ.get(key) == value for key, value in payload["environment"].items()),
         "bounded producer environment changed")
    print(json.dumps(dict(phase="worker-ready", epoch=167, producer_invocation_id=iid,
                          producer_pid=os.getpid(), producer_start_ticks=ticks(os.getpid()),
                          worker_ready_unix_seconds=int(time.time()), payload_sha256=payload_sha),
                     sort_keys=True, separators=(",", ":")), flush=True)
    finish = time.monotonic() + 240
    while time.monotonic() < finish:
        if match_permit(ALIAS/"barrier/allow", iid):
            projected(payload)
            os.execve(payload["argv"][0], payload["argv"], os.environ)
        time.sleep(.2)
    raise TimeoutError("first guard, fenced reprice and permit did not arrive")


def snapshot_stamp():
    available = os.statvfs(HOME)
    mem = dict(row.split(":", 1) for row in Path("/proc/meminfo").read_text().splitlines())
    return (available.f_bavail * available.f_frsize, int(mem["MemAvailable"].split()[0]) * 1024)


def fleet_authority(fleet_ref):
    fleet = read(fleet_ref)
    path = Path(fleet_ref["path"])
    need(path == RT/path.parent.name/"ROOT_COMPLETE_OPERATIONAL_FLEET.json", "wrong operational fleet path")
    timer = fleet["sole_next_timer"]
    name = re.fullmatch(r"horizon-observer-(root[A-Za-z0-9-]+)\.timer", timer)
    need(name is not None and not (RT/name[1]/path.name).exists(), "superseded fleet")
    receiver = props(timer, ("Id", "LoadState", "ActiveState", "SubState", "Job"))
    need(receiver["ActiveState"] == "active" and receiver["SubState"] == "waiting" and not receiver["Job"],
         "sole next fleet timer is no longer waiting")
    read(fleet["sole_next_observer"])
    terminal = read(TERMINAL)
    row = fleet["cold167_execution_failure"]
    need(row["terminal"] == TERMINAL and row["retained_cap_bytes"] == CAP
         and row["resource_credit_bytes"] == row["reservation_ending_bytes"] == 0
         and row["admission"] == terminal["admission"]
         and terminal["archive_ready"] is False and terminal["publication_authorized"] is False
         and fleet.get("current_homefloor_cold166_167_168_170_owners", {}).get("167") is None
         and all(all(item["epoch"] != 167 for item in fleet[key])
                 for key in ("actual_executing_replays", "actual_active_bootstraps", "actual_active_private_diagnostics")),
         "fleet does not preserve the stopped epoch 167 booking")
    active = read(V31_ACTIVE)["new"]
    seal = read(V31_SEAL)
    observer = props(active["unit"], STATE)
    need(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
         and observer["InvocationID"] == active["invocation_id"]
         and observer["MainPID"] == str(active["pid"]) and observer["ActiveState"] == "active"
         and observer["SubState"] == "running" and ticks(active["pid"]) == active["start_ticks"],
         "V31 sole writer changed")
    return fleet, active


def sealed_deployment(prepared, seal_ref):
    need(Path(seal_ref["path"]).parent == PACKAGE, "wrong candidate package location")
    gate = present_member(seal_ref, "replay167.py", executable=True)
    payload = present_member(seal_ref, "payload.json")
    checkpoints = present_member(seal_ref, "epoch-hashes.txt")
    need(gate["sha256"] == prepared["gate_source_sha256"]
         and payload["sha256"] == prepared["payload"]["sha256"]
         and checkpoints["sha256"] == prepared["checkpoints"]["sha256"] == digest(CHECKPOINTS),
         "sealed candidate differs from its preparation")
    data = read(payload)
    verify_payload(data)
    return data, gate, payload, checkpoints


def private_log():
    leaf = LOG.lstat()
    need(LOG.resolve(strict=True) == LOG and stat.S_ISREG(leaf.st_mode) and leaf.st_nlink == 1
         and (leaf.st_uid, leaf.st_gid, stat.S_IMODE(leaf.st_mode)) == (0, 0, 0o600),
         "log must be precreated as a root-only append file")
    return dict(path=str(LOG), device=leaf.st_dev, inode=leaf.st_ino)


def producer_argv(intent, payload, gate_ref, payload_ref, checkpoints):
    mappings = [(item["source"]["path"], item["target"]) for item in payload["files"]]
    mappings += [(gate_ref["path"], str(ALIAS/"replay167.py")),
                 (payload_ref["path"], str(ALIAS/"payload.json")),
                 (checkpoints["path"], str(ALIAS/"epoch-hashes.txt")),
                 (str(ROOT/"barrier"), str(ALIAS/"barrier"))]
    props = [
        "Type=exec", "KillMode=control-group", "TimeoutStopSec=2min", "Restart=no",
        f"MemoryMax={MEMORY}", f"MemoryHigh={MEMORY_HIGH}", "MemorySwapMax=0",
        f"CPUQuota={CPU//10_000}%", "TasksMax=1024", "OOMPolicy=stop", "Nice=5",
        "IOWeight=20", "UMask=0077", "User=sol", "Group=horizon", "LimitNOFILE=1048576",
        "NoNewPrivileges=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateIPC=yes",
        "ProtectSystem=strict", "ProtectHome=read-only",
        "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777,size=64M /home/sol:ro,noexec,nosuid,nodev,mode=0755,size=1M",
        "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
        "RestrictNamespaces=cgroup", "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
        "SystemCallArchitectures=native", "CapabilityBoundingSet=", "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", f"WorkingDirectory={ALIAS}",
        f"BindPaths={RUN}", f"ReadWritePaths={RUN}",
        "BindReadOnlyPaths=" + " ".join(f"{src}:{dest}" for src, dest in mappings),
        f"StandardOutput=append:{LOG}", f"StandardError=append:{LOG}",
        "RuntimeMaxSec=21600",
    ]
    need(intent["payload"] == payload_ref, "wrong candidate command payload")
    env = dict(payload["environment"], HORIZON167_PAYLOAD_SHA256=payload_ref["sha256"])
    return ["/usr/bin/systemd-run", f"--unit={UNIT}", "--description=private-epoch-167-bounded-checkpoints",
            *(f"--property={value}" for value in props),
            *(f"--setenv={key}={value}" for key, value in env.items()),
            "--", "/usr/bin/python3", "-IB", str(ALIAS/"replay167.py"), "gate"]


def quote_population(quote, fleet, actor):
    joined = quote["joined_native_population"]
    want = {PEER146, PEER168, PEER172} | ({UNIT} if actor else set())
    need(want == set(joined), "incorrect phase-specific replay population")
    for key, unit in (("current_full146", PEER146), ("current_joint168_checkpoint", PEER168)):
        row = fleet[key]
        need(row["unit"]["Id"] == unit and row["phase"] == "worker"
             and joined[unit] == [[int(row["unit"]["MainPID"]), row["start_ticks"]]
                                  if key == "current_full146" else row["processes"][0][:2],
                                  [row["worker"]["pid"], row["worker"]["start_ticks"]]],
             f"native peer identity changed: {unit}")
    row, = (entry for entry in fleet["actual_executing_replays"] if entry["epoch"] == 172)
    need(len(joined[PEER172]) == 2 and
         joined[PEER172][0] == [int(row["unit"]["MainPID"]), row["start_ticks"]],
         "native epoch 172 identity changed")
    if actor:
        need(joined[UNIT] == [actor["processes"][0][:2]], "held 167 gate was absent from capacity census")


def quote_base(quote, fleet, fleet_ref, active, actor):
    pod = quote["full146"]["native_successor_quote"]
    route = quote["full146"]
    fit = quote["fit"]
    now = int(time.time())
    need(quote["schema"] == "horizon-epoch168-joint-reduced-combined-fit-v1" and quote["mode"] == "active"
         and all(part["fleet"] == fleet_ref and part["resource_credit_bytes"] == 0
                 and part["recorded_unix_seconds"] == quote["recorded_unix_seconds"]
                 and part["replay_launch_authorized"] is False for part in (quote, route, pod))
         and 0 <= now - quote["recorded_unix_seconds"] <= MAX_AGE
         and quote["archive_publication_authorized"] is False
         and pod["status_registration"]["consumer_seal"] == V31_SEAL
         and all(pod["status_registration"][key] == active[key] for key in ("pid", "start_ticks", "invocation_id"))
         and pod["epoch170_metered_full"]["stage"] == "retained"
         and pod.get("bounded167_owner") == actor
         and pod.get("stopped_generation_resident_credit_bytes") == 0
         and pod["complete_cpu_quota_micros"] == 64_000_000
         and pod["complete_memory_plus_reserve_bytes"] == 810_658_050_048
         and route["retained_185_restore_overlap_bytes"] == 123_350_028_052
         and route["retained_185_restore_enlargement_bytes"] == 54_016_054_271,
         "unbound native population, allocation, 185 reserve, or phase")
    quote_population(quote, fleet, actor)
    book = pod["bookings"]["167"]
    retained = pod["retained_167"]
    need(retained["terminal"] == TERMINAL
         and retained["guard_floor_bytes"] == ORIGINAL_FLOOR
         and retained["resource_credit_bytes"] == retained["reservation_ending_bytes"] == 0
         and retained["booking"] == book and book["root"] == str(LANE)
         and 0 < book["physical_bytes"] < CAP and book["physical_bytes"]+book["remaining_bytes"] == book["cap_bytes"] == CAP
         and book["measurement"] == "two complete stopped-tree walks"
         and pod["replacements"].get("167") is None,
         "the original stopped epoch 167 booking changed")
    need(fit["fits"] is True and route["fit"]["fits"] is True,
         "current incumbents do not fit the native HOME, RAM or guard envelope")
    need(fit["extra_cpu_quota_micros"] == 0
         and fit["extra_memory_bytes"] == 52 * GIB
         and fit["required_available_memory_bytes"] == route["fit"]["projected_required_memory_bytes"] + 52 * GIB
         and route["fit"]["projected_home_floor_bytes"] + quote["joint168"]["stop_allowance_bytes"]
             <= quote["joint168"]["guard_floor_bytes"]
         and fit["required_home_bytes"] == quote["joint168"]["guard_floor_bytes"]+quote["joint168"]["remaining_home_bytes"],
         "wrong combined HOME and RAM equation")
    donor = pod["epoch159_donor_cover"]
    need(donor["fleet"] == fleet_ref and donor["native_recorded_unix_seconds"] == quote["recorded_unix_seconds"]
         and 0 <= donor["remaining_home_bytes"], "wrong retained donor")
    return book, guard_floor(pod, quote), donor["remaining_home_bytes"], fit


def capture(request_ref, *, intent_ref=None, actor=None):
    request = read(request_ref)
    need(request["schema"] == "horizon-epoch167-bounded-capacity-request-v1", "wrong capacity request")
    fleet_ref = request["fleet"]
    fleet, active = fleet_authority(fleet_ref)
    need(request["capacity_deployment"]["path"] == str(CAPACITY_DEPLOYMENT/"deployment-seal-receipt.json"),
         "wrong bounded capacity provider")
    capacity = present_member(request["capacity_deployment"], "post-stop-fit")
    read(request["full146_request"])
    read(request["joint168_request"])
    args = ["/usr/bin/python3", "-IB", capacity["path"], "--full170=retained",
            "--full146-request", request["full146_request"]["path"], request["full146_request"]["sha256"],
            "--joint168-request", request["joint168_request"]["path"], request["joint168_request"]["sha256"]]
    if actor:
        args += ["--bounded167-request", intent_ref["path"], intent_ref["sha256"]]
    args += ["145", fleet_ref["path"], fleet_ref["sha256"]]
    before = snapshot_stamp()
    raw = command(args, timeout=100)
    after = snapshot_stamp()
    quote = json.loads(raw)
    need(fleet_authority(fleet_ref) == (fleet, active) and read(request_ref) == request,
         "fleet or phase request changed during capacity capture")
    book, absolute, donor, fit = quote_base(quote, fleet, fleet_ref, active, actor)
    disk = min(before[0], after[0], fit["available_home_bytes"], fleet["complete_cycle_conservative_available_DATA_bytes"])
    memory = min(before[1], after[1], fit["available_memory_bytes"])
    need(fit["required_available_memory_bytes"] <= memory,
         f"epoch 167 RAM shortfall {fit['required_available_memory_bytes']-memory} bytes")
    return dict(fleet=fleet_ref, provider=request["capacity_deployment"], program=capacity, stdout_sha256=digest(raw),
                recorded_unix_seconds=quote["recorded_unix_seconds"], writer=active,
                population=quote["joined_native_population"], booking=book, incumbent_home=fit["required_home_bytes"],
                strongest_floor=absolute, original_donor_bytes=donor, available_home=disk,
                required_ram=fit["required_available_memory_bytes"], available_ram=memory)


def prestart(prepared_ref, seal_ref, request_ref):
    prepared = read(prepared_ref)
    payload, _, payload_ref, _ = sealed_deployment(prepared, seal_ref)
    fresh_outputs()
    run_directories()
    child(ROOT/"barrier", 0, 0, 0o755)
    child(ROOT/"guard-receipts", 0, 0, 0o700)
    need(not permit_exists() and not (ROOT/"guard-receipts/stop-intent.json").exists(), "dirty admission state")
    for unit in (UNIT, TIMER, GUARD_SERVICE, OLD):
        idle(unit)
    append = private_log()
    need(LOG.lstat().st_size == 0, "gate log is not empty")
    for item in payload["files"]:
        need(file_identity(item["source"]["path"], executable=item["executable"]) == item["source"]["identity"],
             f"prepared input changed: {item['target']}")
    price = capture(request_ref)
    current = price["incumbent_home"]
    remaining = price["booking"]["remaining_bytes"]
    floor, required = funding(current, current, price["strongest_floor"], remaining,
                              price["original_donor_bytes"], price["available_home"])
    need(MEMORY <= 68 * GIB and GUARD_MEMORY == GIB and CPU <= 9_000_000,
         "candidate cap exceeds its stopped booking")
    return dict(schema="horizon-epoch167-bounded-start-intent-v1", epoch=167, terminal=TERMINAL,
                prepared=prepared_ref, deployment=seal_ref, payload=payload_ref, request=request_ref,
                prestart=price, producer_unit=UNIT, armed_floor=floor, required_home=required, append_log=append,
                producer_memory_bytes=MEMORY, guard_memory_bytes=GUARD_MEMORY, resource_credit_bytes=0,
                additional_cpu_quota_micros=0, additional_booked_memory_bytes=0,
                archive_publication_authorized=False, replay_launch_authorized=False)


def intent_data(reference, *, live=False):
    intent = read(reference)
    need(Path(reference["path"]) == ROOT/"START_INTENT.json"
         and intent["schema"] == "horizon-epoch167-bounded-start-intent-v1"
         and intent["terminal"] == TERMINAL and intent["producer_unit"] == UNIT
         and intent["epoch"] == 167 and intent["archive_publication_authorized"] is False
         and intent["replay_launch_authorized"] is False and intent["resource_credit_bytes"] == 0
         and private_log() == intent["append_log"], "wrong epoch 167 start intent")
    payload, gate_ref, payload_ref, checkpoints = sealed_deployment(read(intent["prepared"]), intent["deployment"])
    need(payload_ref == intent["payload"], "intent payload mismatch")
    if live:
        return intent, payload, gate_ref, payload_ref, checkpoints
    need(0 <= int(time.time()) - intent["prestart"]["recorded_unix_seconds"] <= MAX_AGE
         and not permit_exists(), "start intent exceeded its native capture window")
    need(fleet_authority(intent["prestart"]["fleet"])[1] == intent["prestart"]["writer"], "writer changed")
    return intent, payload, gate_ref, payload_ref, checkpoints


def native_owner(intent_ref):
    intent, payload, gate_ref, payload_ref, checkpoints = intent_data(intent_ref, live=True)
    need(not permit_exists(), "permit already exists")
    fields = STATE + ("NRestarts", "Restart", "User", "Group", "KillMode")
    state = props(UNIT, fields)
    pid = int(state["MainPID"])
    iid = state["InvocationID"]
    need(state["ActiveState"] == "active" and state["SubState"] == "running" and pid > 1
         and IID.fullmatch(iid) and int(iid, 16) and state["ControlPID"] == "0"
         and state["ControlGroup"] == CGROUP and not state["Job"] and state["NRestarts"] == "0"
         and state["Restart"] == "no" and state["User"] == "sol" and state["Group"] == "horizon"
         and state["KillMode"] == "control-group", "PID1 does not have the held private gate")
    process = Path(f"/proc/{pid}")
    group = KERNEL / CGROUP.lstrip("/")
    start_ticks = ticks(pid)
    limits(group)
    need((group/"cgroup.procs").read_text().split() == [str(pid)]
         and (process/"cgroup").read_text().strip() == f"0::{CGROUP}", "held process census differs")
    interpreter = Path("/usr/bin/python3").stat()
    binary = (process/"exe").stat()
    need(os.path.samestat(interpreter, binary)
         and (process/"cmdline").read_bytes().split(b"\0") ==
            [b"/usr/bin/python3", b"-IB", os.fsencode(ALIAS/"replay167.py"), b"gate", b""],
         "different held gate command")
    status = (process/"status").read_text().splitlines()
    for label, value in (("Uid:", "1001"), ("Gid:", "1003")):
        need(next(line for line in status if line.startswith(label)).split()[1:] == [value] * 4,
             "gate has an unexpected UID or GID")
    proof_files = [(gate_ref, ALIAS/"replay167.py"), (payload_ref, ALIAS/"payload.json"),
                   (checkpoints, ALIAS/"epoch-hashes.txt")]
    for item, guest in proof_files:
        st = (process/"root"/guest.relative_to("/")).stat()
        need(identity(st) == file_identity(item["path"]), f"gate projection changed {guest}")
    for item in payload["files"]:
        path = process/"root"/Path(item["target"]).relative_to("/")
        need(identity(path.stat()) == item["source"]["identity"], f"input crossed gate: {item['target']}")
    barrier = process/"root"/(ALIAS/"barrier").relative_to("/")
    need(os.path.samestat(barrier.stat(), (ROOT/"barrier").stat()), "gate bound a different permit directory")
    mounts = (process/"mountinfo").read_text().splitlines()
    for guest in (ALIAS/"barrier", *(guest for _, guest in proof_files),
                  *(Path(item["target"]) for item in payload["files"])):
        need(any(fields[4] == str(guest) and "ro" in fields[5].split(",")
                 for line in mounts if len(fields := line.split()) > 5), f"missing read-only bind {guest}")
    for fd in ("1", "2"):
        meta = (process/"fd"/fd).stat()
        need([meta.st_dev, meta.st_ino] == [intent["append_log"]["device"], intent["append_log"]["inode"]],
             "held gate append FD mismatch")
    with LOG.open("rb") as handle:
        data = handle.read(8192)
    need(0 < len(data) < 8192 and len(data.splitlines()) == 1, "gate readiness is absent or ambiguous")
    ready = json.loads(data)
    need(ready["phase"] == "worker-ready" and ready["epoch"] == 167
         and ready["producer_invocation_id"] == iid and ready["producer_pid"] == pid
         and ready["producer_start_ticks"] == start_ticks
         and ready["payload_sha256"] == payload_ref["sha256"]
         and 0 <= int(time.time()) - ready["worker_ready_unix_seconds"] < 240, "foreign gate readiness")
    need(ticks(pid) == start_ticks and props(UNIT, fields) == state
         and (group/"cgroup.procs").read_text().split() == [str(pid)] and not permit_exists(),
         "held native gate changed during capture")
    return dict(unit=UNIT, producer_unit=UNIT, producer_invocation_id=iid, producer_pid=pid,
                start_ticks=start_ticks, ready_at=ready["worker_ready_unix_seconds"],
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                processes=[[pid, start_ticks, binary.st_dev, binary.st_ino]], intent=intent_ref)


def reprice(intent_ref, actor, guard=None):
    intent, *_ = intent_data(intent_ref, live=True)
    current = capture(intent["request"], intent_ref=intent_ref, actor=actor)
    prestart = intent["prestart"]
    for key in ("writer", "fleet", "provider", "program"):
        need(prestart[key] == current[key], f"admission {key} changed between phases")
    need(prestart["population"] == {unit: rows for unit, rows in current["population"].items() if unit != UNIT}
         and native_owner(intent_ref) == actor, "peer or candidate changed during repricing")
    book = current["booking"]
    basis = prestart["booking"]
    need(all(book[key] == basis[key] for key in ("cap_bytes", "root", "run", "stable_root", "historical_realized_bytes")),
         "epoch 167 whole-tree identity changed before release")
    physical = min(book["physical_bytes"], basis["physical_bytes"])
    available = current["available_home"]
    if guard:
        physical = min(physical, guard["physical_bytes"])
        available = min(available, guard["available_home"])
    remaining = CAP - physical
    incumbent = current["incumbent_home"]
    floor, required = funding(incumbent, incumbent, current["strongest_floor"], remaining,
                              current["original_donor_bytes"], available, intent["armed_floor"],
                              book["physical_bytes"] - physical)
    return dict(schema="horizon-epoch167-bounded-stage-price-v1", phase="post-guard" if guard else "held",
                intent=intent_ref, actor=actor, native=current, first_guard=guard, physical_bytes=physical,
                whole_tree_remaining_bytes=remaining, guard_floor_bytes=floor,
                required_home_bytes=required, available_home_bytes=available,
                producer_memory_bytes=MEMORY, guard_memory_bytes=GUARD_MEMORY,
                resource_credit_bytes=0, archive_publication_authorized=False, replay_launch_authorized=False)


def guard_plan(intent_ref, held_ref):
    intent, *_ = intent_data(intent_ref, live=True)
    actor = native_owner(intent_ref)
    held = read(held_ref)
    need(held["schema"] == "horizon-epoch167-bounded-stage-price-v1" and held["phase"] == "held"
         and held["intent"] == intent_ref and held["actor"] == actor
         and held["guard_floor_bytes"] == intent["armed_floor"]
         and 0 <= int(time.time()) - held["native"]["recorded_unix_seconds"] <= MAX_AGE,
         "guard requires the fresh held quote")
    for unit in (TIMER, GUARD_SERVICE):
        idle(unit)
    return dict(schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=UNIT,
                invocation_id=actor["producer_invocation_id"], filesystem=str(HOME),
                worker_root=str(LANE), maximum_worker_vmas=MAX_VMAS, minimum_free_bytes=intent["armed_floor"],
                maximum_root_physical_bytes=CAP, receipt_directory=str(ROOT/"guard-receipts"))


def native_static_validation(plan_ref):
    args = [str(GUARD), plan_ref["path"], "--plan-sha256", plan_ref["sha256"],
            "--self-sha256", GUARD_SHA, "--validate-plan-only"]
    evidence = json.loads(command(args))
    need(evidence == dict(schema="jetstreamer-horizon-standalone-static-plan-validation-v1",
                          plan_sha256=plan_ref["sha256"], self_sha256=GUARD_SHA,
                          validated=True, unit=UNIT, resource_samples_taken=0,
                          replay_launch_authorized=False, protective_guard_proven=False,
                          producer_signaled=False, remote_mutations=False, r2_mutations=False),
         "sealed guard did not validate the exact plan statically")
    return evidence


def guard_argv(plan_ref):
    plan = read(plan_ref)
    need(Path(plan_ref["path"]) == ROOT/"ACTUAL_GUARD_PLAN.json"
         and plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
         and plan["unit"] == UNIT and plan["worker_root"] == str(LANE)
         and plan["filesystem"] == str(HOME) and plan["maximum_root_physical_bytes"] == CAP
         and plan["maximum_worker_vmas"] == MAX_VMAS and plan["minimum_free_bytes"] >= ORIGINAL_FLOOR
         and plan["receipt_directory"] == str(ROOT/"guard-receipts")
         and props(UNIT, STATE)["InvocationID"] == plan["invocation_id"] and not permit_exists(),
         "guard plan does not match the held producer")

    guard_binary()
    native_static_validation(plan_ref)
    arguments = [
        "User=root", "Group=root", "UMask=0077", "Restart=no", f"MemoryMax={GUARD_MEMORY}",
        "MemorySwapMax=0", f"CPUQuota={GUARD_CPU//10_000}%", "TasksMax=256",
        "TimeoutStartSec=120", "TimeoutStopSec=15", "PrivateNetwork=yes", "ProtectSystem=strict",
        "ProtectHome=read-only", "PrivateTmp=yes", "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        f"ReadWritePaths={ROOT/'guard-receipts'}",
        "StandardOutput=journal", "StandardError=journal",
    ]
    for unit in (TIMER, GUARD_SERVICE):
        idle(unit)
    return ["/usr/bin/systemd-run", f"--unit={TIMER.removesuffix('.timer')}", "--on-active=1s",
            "--on-unit-inactive=10s", "--timer-property=AccuracySec=1s", "--service-type=oneshot",
            *(f"--property={value}" for value in arguments),
            "--", str(GUARD), plan_ref["path"], "--plan-sha256", plan_ref["sha256"],
            "--self-sha256", GUARD_SHA]


def sample_proof(plan, sample, actor, plan_ref, sample_ref, timer, service):
    iid = actor["producer_invocation_id"]
    now = int(time.time())
    producer = sample["producer"]
    walk = sample["root_physical_observation"]
    need(Path(plan_ref["path"]) == ROOT/"ACTUAL_GUARD_PLAN.json"
         and plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
         and plan["unit"] == UNIT and plan["invocation_id"] == iid
         and plan["worker_root"] == str(LANE) and plan["filesystem"] == str(HOME)
         and plan["receipt_directory"] == str(ROOT/"guard-receipts")
         and plan["maximum_root_physical_bytes"] == CAP and plan["maximum_worker_vmas"] == MAX_VMAS
         and plan["minimum_free_bytes"] >= ORIGINAL_FLOOR, "guard plan crossed the held actor")
    need(timer["ActiveState"] == "active" and timer["SubState"] in ("waiting", "running")
         and not timer["Job"] and IID.fullmatch(timer["InvocationID"]) and timer["Triggers"] == GUARD_SERVICE
         and service["TriggeredBy"] == TIMER and service["CPUQuotaPerSecUSec"] == "250ms"
         and service["MemoryMax"] == str(GUARD_MEMORY) and service["MemorySwapMax"] == "0"
         and all(value in service["ExecStart"] for value in (str(GUARD), GUARD_SHA, plan_ref["path"], plan_ref["sha256"])),
         "native guard timer, limits or sealed command changed")
    guard_iid = sample["guard_invocation_id"]
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and IID.fullmatch(guard_iid) and sample["plan"] == plan_ref["path"]
         and Path(sample_ref["path"]) == ROOT/"guard-receipts"/f"sample-{guard_iid}.json"
         and sample["plan_sha256"] == plan_ref["sha256"]
         and sample.get("guard_sha256", sample.get("self_sha256")) == GUARD_SHA
         and sample["producer_invocation_id"] == producer["invocation_id"] == iid
         and producer["pid"] == actor["producer_pid"] and producer["cgroup"] == CGROUP
         and producer["active"] == "active" and producer["restarts"] == 0
         and actor["ready_at"] <= sample["recorded_unix_seconds"] <= now
         and now - sample["recorded_unix_seconds"] <= MAX_AGE
         and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["worker_observation_error"] is None and sample["root_physical_observation_error"] is None
         and sample["workers"] == [] and walk["exceeds_budget"] is False
         and sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and sample["maximum_root_physical_bytes"] == CAP
         and sample["available_bytes"] >= plan["minimum_free_bytes"], "first guard crossed or failed")
    copies = [walk[key] for key in ("first", "second")]
    need(all(0 < copy["physical_bytes"] <= CAP and copy["vanished_entries"] == 0 for copy in copies),
         "first guard tree census is unstable or over cap")
    return dict(plan=plan_ref, sample=sample_ref, timer_invocation_id=timer["InvocationID"],
                guard_invocation_id=guard_iid, available_home=sample["available_bytes"],
                physical_bytes=min(copy["physical_bytes"] for copy in copies),
                floor=plan["minimum_free_bytes"], recorded_unix_seconds=sample["recorded_unix_seconds"])


def first_guard(intent_ref, plan_ref, sample_ref):
    actor = native_owner(intent_ref)
    intent, *_ = intent_data(intent_ref, live=True)
    timer = props(TIMER, ("Id", "LoadState", "InvocationID", "ActiveState", "SubState", "Job", "Triggers"))
    service = props(GUARD_SERVICE, ("Id", "LoadState", "ExecStart", "TriggeredBy", "CPUQuotaPerSecUSec",
                                   "MemoryMax", "MemorySwapMax"))
    proof = sample_proof(read(plan_ref), read(sample_ref), actor, plan_ref, sample_ref, timer, service)
    guard_unit = f"_SYSTEMD_UNIT={GUARD_SERVICE}"
    invocation = f"_SYSTEMD_INVOCATION_ID={proof['guard_invocation_id']}"
    entries = command(["/usr/bin/journalctl", "--no-pager", "-q", "-o", "json", guard_unit, invocation]).splitlines()
    need(any(json.loads(entry).get("_EXE") == str(GUARD) for entry in entries),
         "first guard has no invocation-bound native journal evidence")
    need(proof["floor"] == intent["armed_floor"] and native_owner(intent_ref) == actor
         and not (ROOT/"guard-receipts/stop-intent.json").exists(), "first guard changed before handoff")
    return dict(schema="horizon-epoch167-bounded-first-guard-v1", intent=intent_ref, actor=actor, **proof)


def reread_guard(intent_ref, guard):
    need(guard == first_guard(intent_ref, guard["plan"], guard["sample"]), "first guard proof changed")
    return guard


def release(intent_ref, post_ref):
    need(Path(post_ref["path"]) == ROOT/"POST_GUARD_CAPACITY.json", "different post-guard receipt path")
    actor = native_owner(intent_ref)
    post = read(post_ref)
    need(post["schema"] == "horizon-epoch167-bounded-stage-price-v1" and post["phase"] == "post-guard"
         and post["intent"] == intent_ref and post["actor"] == actor and post["resource_credit_bytes"] == 0
         and post["archive_publication_authorized"] is post["replay_launch_authorized"] is False
         and 0 <= int(time.time()) - post["native"]["recorded_unix_seconds"] <= MAX_AGE,
         "stale or crossed final capacity receipt")
    need(not (ROOT/"guard-receipts/stop-intent.json").exists(), "guard has tripped")
    guard = reread_guard(intent_ref, post["first_guard"])
    intent, *_ = intent_data(intent_ref, live=True)
    disk, mem = snapshot_stamp()
    need(guard["floor"] == intent["armed_floor"] == post["guard_floor_bytes"]
         and post["required_home_bytes"] == post["guard_floor_bytes"] + post["whole_tree_remaining_bytes"]
         and disk >= post["required_home_bytes"] and mem >= post["native"]["required_ram"]
         and fleet_authority(post["native"]["fleet"])[1] == post["native"]["writer"],
         "admission no longer fits at permit time")
    iid = actor["producer_invocation_id"].encode()
    receipt = dict(schema="horizon-epoch167-bounded-authorized-release-v1", intent=intent_ref,
                   post_guard_capacity=post_ref, actor=actor, guard_sample=guard["sample"],
                   permit_sha256=digest(iid), archive_publication_authorized=False, resource_credit_bytes=0)
    path = ROOT/"AUTHORIZED_RELEASE.json"
    if path.exists():
        receipt_ref = ref(path, digest(encode(receipt)))
        need(read(receipt_ref) == receipt, "an earlier release owns this start intent")
    else:
        receipt_ref = atomic(path, encode(receipt))
    need(native_owner(intent_ref) == actor and not (ROOT/"guard-receipts/stop-intent.json").exists(),
         "held producer or guard changed before permit")
    permit = atomic(ROOT/"barrier/allow", iid, 0o444)
    return dict(receipt=receipt_ref, permit=permit)


def main():
    if os.sys.argv[1:] == ["gate"]:
        gate()
        return
    need(os.geteuid() == 0 and os.getegid() == 0, "root operational evidence is required")
    args = cli_args()
    op = args.operation
    if op == "prepare":
        row = prepare(ref(args.spec, args.sha256), Path(args.output_dir))
    elif op == "prestart":
        row = prestart(ref(args.prepared, args.sha256), ref(PACKAGE/"deployment-seal-receipt.json", args.package_seal_sha256),
                       ref(args.request, args.request_sha256))
    elif op == "guard-argv":
        row = guard_argv(ref(args.plan, args.sha256))
    else:
        intent = ref(args.intent, args.sha256)
        if op == "argv":
            row = producer_argv(*intent_data(intent))
        elif op == "owner":
            row = native_owner(intent)
        elif op == "held":
            row = reprice(intent, native_owner(intent))
        elif op == "guard-plan":
            row = guard_plan(intent, ref(args.held, args.held_sha256))
        elif op == "first-guard":
            row = first_guard(intent, ref(args.plan, args.plan_sha256), ref(args.sample, args.sample_sha256))
        elif op == "post-guard":
            guard = reread_guard(intent, read(ref(args.first_guard, args.first_guard_sha256)))
            row = reprice(intent, guard["actor"], guard)
        elif op == "release":
            lock_path = ROOT/"release.lock"
            with os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | FLAGS, 0o600), "rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                row = release(intent, ref(args.post_guard, args.post_guard_sha256))
        else:
            raise ValueError(f"unknown stage: {op}")
    if args.record is not None:
        need(op not in ("release", "owner"), "this phase already records its required outputs")
        record_parent = args.record.parent
        child(record_parent, 0, 0, 0o700)
        row = atomic(args.record, encode(row))
    print(encode(row).decode(), end="")


if __name__ == "__main__":
    main()
