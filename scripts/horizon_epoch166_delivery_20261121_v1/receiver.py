#!/usr/bin/python3 -I
"""Run one local consumer under the recorded source owner's native publication claim."""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from typing import NamedTuple

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch166-terminal-20261121-v1")
LIVE_SHA = "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe"
OWNER = (1001, 1003)
LOCK_ID = (64512, 93717107)
UNIT = "horizon-qualify-independent-cold166-20261120-v1.service"
IID = "fa16ee2f14fe44ecbc37c59e197553ac"
LEGACY = Path("/home/sol/horizon")
WATCH_UNIT = "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service"
WATCH_EXE = "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2-progressive"
NOFOLLOW = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class Producer(NamedTuple):
    epoch: int
    unit: str
    invocation_id: str


ORIGINAL = Producer(166, UNIT, IID)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(m):
    return (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_nlink,
            m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def inode(m):
    return (m.st_dev, m.st_ino)


def directory(path, owner):
    m = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(m.st_mode)
            and m.st_uid == owner and stat.S_IMODE(m.st_mode) == 0o700,
            f"private directory changed: {path}")
    return m


def opened(stack, path):
    require(path.is_absolute() and path.resolve(strict=True) == path, f"aliased path: {path}")
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    stack.callback(os.close, fd)
    m = os.fstat(fd)
    require(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and
            identity(m) == identity(path.lstat()), f"file replaced: {path}")
    return fd


def small(fd, limit):
    n = os.fstat(fd).st_size
    require(0 < n <= limit, "incorrect bounded file length")
    data = os.pread(fd, n + 1, 0)
    require(len(data) == n, "bounded file changed")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def seal(stack, path, mode):
    fd = opened(stack, path)
    m = os.fstat(fd)
    require(m.st_uid == 0 and stat.S_IMODE(m.st_mode) == mode, f"unsafe authority: {path}")
    return small(fd, 1 << 20)


def source_dir(binding):
    path = Path(binding["path"])
    m = directory(path, OWNER[0])
    require(m.st_gid == OWNER[1] and inode(m) == (binding["device"], binding["inode"]),
            f"source directory differs: {path}")
    return path


def watcher():
    pid = int(subprocess.check_output(["/usr/bin/systemctl", "show", WATCH_UNIT,
            "-p", "MainPID", "--value"], timeout=15))
    require(pid > 1, "legacy watcher has no original reader")
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    require(len(argv) > 6 and argv[0] == os.fsencode(WATCH_EXE)
            and Path(f"/proc/{pid}/exe").resolve() == Path(WATCH_EXE)
            and argv[2] == os.fsencode(LEGACY) and argv[4:6] == [b"101", b"200"],
            "legacy watcher source or epoch range changed")
    return LEGACY


def authority(stack, root, expected_digest, producer=ORIGINAL):
    epoch, unit, iid = producer
    directory(root, 0)
    raw_live = seal(stack, root / "LIVE.json", 0o600)
    require(sha(raw_live) == expected_digest, "live authority digest differs")
    live = json.loads(raw_live)
    raw_term = seal(stack, root / "TERMINAL_SUCCESS.json", 0o400)
    term = json.loads(raw_term)
    manager = term["manager_terminal"]
    require(live["schema"] == f"horizon-{epoch}-live-to-terminal-witness-v1" and live["epoch"] == epoch
            and live["native"]["manager"]["Id"] == unit and live["native"]["manager"]["InvocationID"] == iid
            and term["schema"] == f"terminal{epoch}-success-v1" and term["epoch"] == epoch
            and term["producer_unit"] == unit and term["producer_invocation_id"] == iid
            and term["source_admission"] == live["admission"]
            and term["live"] == {"path": str(root / "LIVE.json"), "sha256": expected_digest}
            and term[f"terminal_{epoch}_disposition"] == "node-published-local-cohort"
            and all(term[k] is False for k in ("archive_publication_authorized", "new_producer_authorized", "canonical_r2_verified"))
            and (manager["_PID"], manager["_BOOT_ID"], manager["UNIT"], manager["INVOCATION_ID"], manager["MESSAGE_ID"])
            == ("1", live["boot_id"].replace("-", ""), unit, iid, "7ad2d189f7e94e70a38c781354912448"),
            "terminal authority or original producer differs")
    return live, term, sha(raw_term)


def inherited_program(stack, path, digest):
    fd = opened(stack, path)
    m = os.fstat(fd)
    require(m.st_uid == 0 and not m.st_mode & 0o022 and m.st_mode & 0o111,
            f"unsafe executable: {path}")
    require(sha(small(fd, 128 << 20)) == digest, f"executable digest differs: {path}")
    return fd


def receive(root, expected_digest, lock_id, watched, native, native_hash, consumer, consumer_hash, args, producer=ORIGINAL):
    require(os.geteuid() == 0, "receiver requires root")
    epoch = producer.epoch
    with contextlib.ExitStack() as stack:
        live, term, terminal_hash = authority(stack, root, expected_digest, producer)
        output = source_dir(live["output"])
        batches = source_dir(live["private_batch_receipts"])
        tx = term["transaction_id"]
        require(re.fullmatch("[a-f0-9]{64}", tx) and batches.name ==
                "destination-{:016x}-{:016x}".format(*inode(output.stat()))
                and batches.parent.name == "archive-batches" and batches.parents[1].name == "evidence",
                "transaction or destination scope differs")
        require(watched.resolve(strict=True) == watched and not output.is_relative_to(watched)
                and not watched.is_relative_to(output) and inode(watched.stat()) != inode(output.stat()),
                "isolated source overlaps legacy watcher")
        lock = batches.parents[2] / "locks" / f"epoch-{epoch}.lock"
        lock_fd = opened(stack, lock)
        lm = os.fstat(lock_fd)
        require(inode(lm) == lock_id and (lm.st_uid, lm.st_gid) == OWNER
                and stat.S_IMODE(lm.st_mode) == 0o600, "original producer lock differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        archive = output / f"epoch-{epoch}.jet"
        sidecar = output / f"epoch-{epoch}.jet.sha256"
        receipt = batches / f"batch-{tx}.json"
        require(str(receipt) == term["committed_receipt"]["path"] and
                str(archive) == term["local_archive"]["path"], "terminal names a different batch or archive")
        pinned = {}
        for path in (archive, sidecar, receipt):
            fd = opened(stack, path)
            m = os.fstat(fd)
            require((m.st_uid, m.st_gid) == OWNER, "wrong source owner")
            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            pinned[path] = (fd, identity(m))
        def revalidate():
            require(source_dir(live["output"]) == output and source_dir(live["private_batch_receipts"]) == batches
                    and identity(lock.lstat()) == identity(lm), "source directories or lock changed")
            for path, (fd, before) in pinned.items():
                require(fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK and
                        identity(os.fstat(fd)) == before == identity(path.lstat()), f"source changed: {path}")
        revalidate()
        afd, sfd, rfd = (pinned[p][0] for p in (archive, sidecar, receipt))
        m = os.fstat(afd)
        digest = term["local_archive"]["sha256"]
        require(term["local_archive"] == {"path": str(archive), "device": m.st_dev, "inode": m.st_ino,
                "size": m.st_size, "sha256": digest} and re.fullmatch("[a-f0-9]{64}", digest)
                and small(sfd, 1024) == f"{digest}  {archive.name}\n".encode()
                and sha(small(rfd, 32 << 20)) == term["committed_receipt"]["sha256"],
                "terminal archive, sidecar or receipt changed")
        nfd = inherited_program(stack, native, native_hash)
        output_json = subprocess.check_output([f"/proc/self/fd/{nfd}", "admit", str(epoch),
                str(receipt), live["manifest_fingerprint"].removeprefix("sha256:"), str(watched)],
                user=OWNER[0], group=OWNER[1], extra_groups=(), pass_fds=(nfd,), timeout=30)
        proof = json.loads(output_json)
        require((proof["transaction"], proof["source"], proof["archive"], proof["sidecar"],
                proof["sha256"], proof["uid"]) == (tx, str(output), str(archive), str(sidecar), digest, OWNER[0]),
                "native admission differs from sealed terminal")
        revalidate()
        cfd = inherited_program(stack, consumer, consumer_hash)
        info = {"epoch": epoch, "directory": str(output), "transaction_id": tx, "sha256": digest,
                "terminal_sha256": terminal_hash, "receipt_sha256": term["committed_receipt"]["sha256"],
                "archive_fd": afd, "sidecar_fd": sfd, "receipt_fd": rfd, "epoch_lock_fd": lock_fd}
        # The synchronous consumer inherits the same flock and all three inodes.
        # Kill it on supervisor death, including Linux's default SIGIO lease-break termination.
        parent = os.getpid()
        def bind_lifetime():
            if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
                os._exit(74)
        subprocess.run([f"/proc/self/fd/{cfd}", *args, str(output)],
                env={**os.environ, "HORIZON_SOURCE_HANDOFF": json.dumps(info)},
                pass_fds=(cfd, afd, sfd, rfd, lock_fd), preexec_fn=bind_lifetime, check=True)
        revalidate()
        return {k:v for k,v in info.items() if not k.endswith("_fd")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=Path)
    parser.add_argument("native_sha256")
    parser.add_argument("consumer", type=Path)
    parser.add_argument("consumer_sha256")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    a = parser.parse_args()
    signal.signal(signal.SIGIO, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGIO})
    try:
        print(json.dumps(receive(ROOT, LIVE_SHA, LOCK_ID, watcher(), a.native,
              a.native_sha256, a.consumer, a.consumer_sha256, a.args), sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        sys.exit(str(e))
