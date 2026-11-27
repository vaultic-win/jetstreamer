"""The native epoch 162 private producer, immutable bindings and retained filesystem."""

import hashlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path

G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PRIVATE = Path("/home/sol/.jetstreamer-private")
BASE = RT / "epoch162-first-hourly-completion-20261127-v2"
RUN = PRIVATE / BASE.name
IMAGE = RUN / "mutable.ext4"
DATA = BASE / "split-v1"
PKG = BASE / "issued-split-v1"
GUARDS = BASE / "guard-receipts"
ALLOW = BASE / "barrier/allow"
SUPPORT = PRIVATE / "epoch162-local-capped-20261127.6qaa2Qgr"
HANDOFF = SUPPORT / "LOCAL_OPERATOR_HANDOFF.json"
HANDOFF_SHA = "daceecc4a7f4f6502c43fbcf989da229d561098deb2cccf95b2067f7185d047e"
DONOR = BASE / "SPLIT_AND_166_WATCHERS_1795819276953592886.json"
DONOR_SHA = "64aa76de4fb179a650488d3d53c05050aff7b4fa97ef60c61d3726e42545133c"
UNIT = "horizon-qualify-162-first-hourly-completion-20261127-v2.service"
TIMER = "horizon-guard-162-first-hourly-completion-20261127-v2.timer"
GROUP = "/system.slice/" + UNIT
CGROUP = Path("/sys/fs/cgroup" + GROUP)
GATE = BASE / "static/hold-162-completion"
GUARD = BASE / "static/guard"
GUARD_SHA = "5be30fba437e03fc26f009247714986dfdc6670426650532b5ec166d67fc9183"
MIN_FLOOR = 9_470_567_509_909
CONTROL = 64 * M
HOME_IMAGE = 8 * G
BOOT = Path("/proc/sys/kernel/random/boot_id")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(path):
    st = Path(path).stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_ctime_ns, st.st_mtime_ns]


def digest(path):
    with Path(path).open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def pinned(path, expected=None):
    path = Path(path)
    st = path.lstat()
    need(
        path.resolve(strict=True) == path
        and stat.S_ISREG(st.st_mode)
        and st.st_uid == 0
        and not st.st_mode & 0o022
        and st.st_nlink == 1,
        "untrusted " + str(path),
    )
    data = path.read_bytes()
    ref = {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    need(
        identity(path) == [st.st_dev, st.st_ino, st.st_size, st.st_ctime_ns, st.st_mtime_ns]
        and (expected is None or expected == ref["sha256"]),
        "changed " + str(path),
    )
    return json.loads(data), ref


def bound(ref):
    return pinned(ref["path"], ref["sha256"])[0]


def save(path, value, mode=0o444):
    """Publish one complete receipt. A mismatching existing value is never replaced."""
    data = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    tmp = path.with_name("." + path.name + "-" + str(time.time_ns()))
    with tmp.open("xb") as dest:
        dest.write(data)
        dest.flush()
        os.fchmod(dest.fileno(), mode)
        os.fsync(dest.fileno())
    try:
        try:
            os.link(tmp, path)
        except FileExistsError:
            st = path.lstat()
            need(
                path.resolve(strict=True) == path
                and stat.S_ISREG(st.st_mode)
                and st.st_uid == 0
                and st.st_nlink == 1
                and stat.S_IMODE(st.st_mode) == mode
                and path.read_bytes() == data,
                "existing different " + str(path),
            )
    finally:
        tmp.unlink()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def profile(scratch_gib):
    need(type(scratch_gib) is int and scratch_gib in (32, 36), "unqualified tmpfs size")
    return dict(
        scratch_bytes=scratch_gib * G,
        worker_anonymous_allowance=26 * G,
        producer_memory_max=(scratch_gib + 26) * G,
        guard_memory_max=G,
        combined_ram=(scratch_gib + 27) * G,
        home_image=HOME_IMAGE,
        control=CONTROL,
        producer_cpu_micros=2000000,
        guard_cpu_micros=1000000,
        swap_bytes=0,
    )


def scope():
    packet, _ = pinned(HANDOFF, HANDOFF_SHA)
    return packet


def sources():
    packet = scope()
    rows = packet["profile"]["readonly_projections"]
    for r in rows:
        src = Path(r["source"])
        if "identity" in r:
            need(identity(src) == r["identity"], "changed source inode " + str(src))
    for k in ("node", "capped_worker", "first_hourly_gate", "first_hourly_guard"):
        ref = packet[k]
        need(digest(ref["path"]) == ref["sha256"], "changed executable " + k)
    return rows


def manager(
    name,
    fields="Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup,InvocationID,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", name, "-p", fields], capture_output=True, text=True, timeout=12
    )
    props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    need(
        result.returncode == 0 or result.returncode == 4 and props.get("LoadState") == "not-found",
        "unreadable unit " + name,
    )
    return props


def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])


def prepare_image(directory, image, ledger_members, size=HOME_IMAGE):
    """Keep the regular image beneath the guard's host walk, even while its producer mounts over it."""
    need(
        directory.is_dir() and image.parent == directory and directory.stat().st_dev == PRIVATE.stat().st_dev,
        "not on the charged HOME filesystem",
    )
    seed = directory / "seed"
    seed.mkdir(mode=0o700)
    for name in ("ledger", "private", "scratch"):
        p = seed / name
        p.mkdir(mode=0o700)
        os.chown(p, 1001, 1003)
    for rel in ledger_members:
        need(rel.parts and rel.parts[0] == "ledger" and ".." not in rel.parts, "wrong image projection")
        p = seed / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch(mode=0o644, exist_ok=False)
    with image.open("xb") as f:
        f.truncate(size)
        os.fchmod(f.fileno(), 0o400)
    subprocess.run(
        [
            "/usr/sbin/mkfs.ext4",
            "-q",
            "-F",
            "-b",
            "4096",
            "-m",
            "0",
            "-N",
            "32768",
            "-O",
            "^has_journal",
            "-E",
            "root_owner=1001:1003,lazy_itable_init=1,nodiscard",
            "-d",
            str(seed),
            str(image),
        ],
        check=True,
    )
    st = image.lstat()
    need(
        st.st_size == size and st.st_blocks * 512 < CONTROL and st.st_uid == 0 and st.st_nlink == 1,
        "unexpected initial allocation or owner",
    )
    return [st.st_dev, st.st_ino, st.st_size]


def producer_argv(scratch_gib, packet, bindings):
    plan = profile(scratch_gib)
    options = [
        "Type=exec",
        "User=sol",
        "Group=horizon",
        "Restart=no",
        "RuntimeMaxSec=6300",
        "TimeoutStopSec=20",
        "KillMode=control-group",
        "TasksMax=512",
        "CPUQuota=200%",
        "MemorySwapMax=0",
        "LimitCORE=0",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadOnlyPaths=/tmp /var/tmp",
        "PrivateDevices=yes",
        "PrivateMounts=yes",
        "NoNewPrivileges=yes",
        "ProtectControlGroups=yes",
        "CapabilityBoundingSet=",
        "UMask=0077",
        "WorkingDirectory=" + str(RUN),
        "StandardOutput=journal",
        "StandardError=journal",
        "MemoryMax=" + str(plan["producer_memory_max"]),
        "MemoryHigh=" + str(plan["scratch_bytes"] + 24696061952),
        "MountImages=" + str(IMAGE) + ":" + str(RUN) + ":rw,nosuid,nodev",
        f"TemporaryFileSystem={RUN}/scratch:rw,noswap,size={plan['scratch_bytes']},nr_inodes=1048576,uid=1001,gid=1003,mode=0700",
        "BindReadOnlyPaths=" + " ".join(r["source"] + ":" + r["readonly_view"] for r in bindings),
    ]
    return (
        ["/usr/bin/systemd-run", "--unit=" + UNIT]
        + ["--property=" + v for v in options]
        + ["--setenv=" + k + "=" + v for k, v in packet["profile"]["environment"].items()]
        + ["--", *packet["profile"]["main_argv"]]
    )


def verify_mounts(pid, scratch_gib, expected_image, bindings):
    root = Path(f"/proc/{pid}/root")

    def viewed(path):
        return root / str(path).lstrip("/")

    def mount(path):
        command = [
            "/usr/bin/findmnt",
            "-N",
            str(pid),
            "-M",
            str(path),
            "--json",
            "-o",
            "TARGET,FSTYPE,VFS-OPTIONS,FS-OPTIONS",
        ]
        entries = json.loads(subprocess.check_output(command, text=True))["filesystems"]
        need(len(entries) == 1 and entries[0]["target"] == str(path), "different mount " + str(path))
        return entries[0]

    mem, home = mount(RUN / "scratch"), mount(RUN)
    opts = set((mem["vfs-options"] + "," + mem["fs-options"]).split(","))
    need(
        home["fstype"] == "ext4"
        and "rw" in home["vfs-options"].split(",")
        and mem["fstype"] == "tmpfs"
        and {"rw", "noswap"} <= opts
        and "noexec" not in opts,
        "different physical mounts",
    )
    scratch = os.statvfs(viewed(RUN / "scratch"))
    ledger = os.statvfs(viewed(RUN / "ledger"))
    ds = viewed(RUN).stat().st_dev
    need(
        ds == viewed(RUN / "private").stat().st_dev == viewed(RUN / "ledger").stat().st_dev
        and ds != viewed(RUN / "scratch").stat().st_dev
        and os.major(ds) == 7
        and 0 < ledger.f_blocks * ledger.f_frsize <= HOME_IMAGE
        and scratch.f_blocks * scratch.f_frsize == scratch_gib * G
        and scratch.f_files == 1 << 20
        and expected_image == identity(IMAGE)[:3],
        "changed disk backing or scratch capacity",
    )
    loop = Path(f"/sys/dev/block/{os.major(ds)}:{os.minor(ds)}/loop/backing_file")
    name = Path(loop.read_text().strip())
    candidates = (name, Path("/home/sol") / name.relative_to("/"))
    need(any(p.is_file() and p.samefile(IMAGE) for p in candidates), "wrong loop backing")
    for row in bindings:
        path = row["readonly_view"]
        if "identity" in row:
            need(identity(row["source"]) == row["identity"], "source metadata drifted " + path)
        need(
            "ro" in mount(path)["vfs-options"].split(",") and os.path.samefile(row["source"], viewed(path)),
            "changed read-only projection " + path,
        )
    return dict(
        image=expected_image,
        backing=str(IMAGE),
        disk_device=ds,
        scratch_device=viewed(RUN / "scratch").stat().st_dev,
        scratch_bytes=scratch_gib * G,
        scratch_inodes=scratch.f_files,
        immutable_bindings=len(bindings),
    )


def guard_plan(iid, floor):
    need(type(floor) is int and floor >= MIN_FLOOR and len(iid) == 32 and int(iid, 16) > 0, "invalid guard binding")
    return {
        "schema": "jetstreamer-horizon-standalone-guard-plan-v1",
        "unit": UNIT,
        "invocation_id": iid,
        "filesystem": "/home/sol",
        "minimum_free_bytes": floor,
        "worker_root": str(RUN),
        "maximum_worker_vmas": 3500000,
        "maximum_root_physical_bytes": HOME_IMAGE + CONTROL,
        "receipt_directory": str(GUARDS),
    }
