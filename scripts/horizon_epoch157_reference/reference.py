#!/usr/bin/env python3
"""Private epoch 157 terminal reference. Produces no archive or production commitment."""
import argparse
import base64
import datetime
import hashlib
import json
import os
import stat
import signal
import subprocess
import time
from pathlib import Path

from car import CORRECTIONS, blocks, require
from native import base58, worker

BOOT, ROOT, END, NEXT, DOWNSTREAM = 68249460, 68255828, 68255999, 68256004, 68262721
ARCHIVE_HASH = "4bBRgjRMP97efgSCQk4TWhCPTRcR5A8r9M3LC2jXXs9P"
TERMINAL_BANK = "2FTMDfKT3EkkP7A95VUFKoTfSjJ6ic5YYUszXGk6fv2F"
TERMINAL_POH = "6BBBZAyAH5iVhvMaBKvvhn7UeM1ugtFuYHFV7mxePZch"
SUCCESSOR_BANK = "CejRg8K7YMEvpFrddpYMiSvYjfppGN2BTuSXRbgGCmSZ"
SUCCESSOR_POH = "8cV5NfuprDeZg1EPbqvNe6P4YYAH5MKmugARsnnCnVUg"
DOWNSTREAM_ACCOUNTS = "FyxDsXUW85mkudMtzUbUN4omAS5BT6x2fUjkrNkVEaCy"
SIZE = 1767182259
ROOT_DIR = Path("/home/sol/.jetstreamer-private/epoch157-late-terminal-qualification-v2")
SNAPSHOT = ROOT_DIR / "inputs" / f"snapshot-{BOOT}-{ARCHIVE_HASH}.tar.zst"
GENESIS = ROOT_DIR / "output/genesis.tar.bz2"
MANIFEST = ROOT_DIR / "output/epoch-157-v158-late-terminal.jet.segment.json"
FIELDS = ("slot", "accounts_hash", "bank_hash", "last_blockhash", "capitalization",
          "transaction_count", "tick_height")
MEMORY = 80 << 30
SCRATCH = 96 << 30


def same_state(a, b):
    return all(a[k] == b[k] for k in FIELDS)


def immutable_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def utc():
    return datetime.datetime.now(datetime.UTC).isoformat()


def source_probe():
    proofs = []
    edges = [(157, END, END-1, TERMINAL_POH), (158, NEXT, END, SUCCESSOR_POH)]
    edges.extend((slot//432000, slot, row["parent"], row["blockhash"])
                 for slot, row in CORRECTIONS.items())
    for ep, target, parent, poh in sorted(edges):
        [(slot, actual_parent, entries)] = blocks(ep, target, target)
        require((slot, actual_parent, base58(entries[-1][1])) == (target, parent, poh), "edge")
        proofs.append(dict(slot=slot, parent=actual_parent, last_entry=poh, entries=len(entries),
                           transactions=sum(len(row[2]) for row in entries)))
    for version in (8, 6):
        with worker(version):
            pass
    return dict(as_of=utc(), edges=proofs, native_handshakes=[8, 6], bank_opened=False)


def admitted(scratch, receipts):
    require(os.getuid() != 0 and scratch.is_absolute() and scratch.resolve() == scratch and
            receipts.is_absolute() and receipts.resolve() == receipts and
            receipts.is_relative_to(Path("/home/sol/.jetstreamer-private")), "private reference paths")
    for path in (scratch, receipts):
        st = path.stat()
        require(st.st_uid == os.getuid() and stat.S_ISDIR(st.st_mode) and
                stat.S_IMODE(st.st_mode) == 0o700 and
                all(path == scratch and member.name == "lost+found" and member.is_dir()
                    for member in path.iterdir()),
                "empty private attempt directories required")
    # The enclosing physical-admission process reserves a fixed ext4 loop file
    # on HOME; this makes growth exceedance a contained ENOSPC on this attempt.
    vol = os.statvfs(scratch)
    require(scratch.is_mount() and 80 << 30 <= vol.f_bavail * vol.f_frsize <= SCRATCH and
            vol.f_files > 400000, "reference filesystem envelope")
    source, filesystem = subprocess.check_output(
        ["findmnt", "-n", "-o", "SOURCE,FSTYPE", "-T", scratch], text=True).split()
    require(filesystem == "ext4" and source.startswith("/dev/loop") and source[9:].isdecimal(),
            "reference scratch loop device")
    backing = Path((Path("/sys/block") / Path(source).name / "loop/backing_file").read_text().strip())
    backing_stat = backing.stat()
    require(backing.is_relative_to(Path("/home/sol/.jetstreamer-private")) and
            backing_stat.st_dev == receipts.stat().st_dev and backing_stat.st_size == SCRATCH and
            backing_stat.st_blocks * 512 >= SCRATCH and not os.access(backing, os.W_OK),
            "fully allocated HOME scratch image")
    rel = Path("/proc/self/cgroup").read_text().strip().removeprefix("0::").lstrip("/")
    cg = Path("/sys/fs/cgroup") / rel
    quota, period = (cg / "cpu.max").read_text().split()
    require(int(quota) == 2 * int(period) and int((cg/"memory.max").read_text()) == MEMORY and
            int((cg/"memory.swap.max").read_text()) == 0, "reference cgroup envelope")
    return dict(cgroup=str(cg), scratch_image=str(backing), scratch=SCRATCH, memory=MEMORY,
                cpu_cores=2, swap=0)


def lookup_inputs():
    raw = MANIFEST.read_bytes()
    require(hashlib.sha256(raw).hexdigest() ==
            "f6b6b7388f80ee06b0c9b23125020d8b616736b89455bf488dadcfe082aab5cf",
            "retained original checkpoint manifest")
    require(hashlib.sha256(GENESIS.read_bytes()).hexdigest() ==
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            "genesis archive")
    md5, sha = hashlib.md5(usedforsecurity=False), hashlib.sha256()
    with SNAPSHOT.open("rb") as f:
        st = os.fstat(f.fileno())
        require(st.st_size == SIZE and stat.S_ISREG(st.st_mode), "snapshot length")
        for buf in iter(lambda: f.read(4 << 20), b""):
            md5.update(buf)
            sha.update(buf)
        change = os.fstat(f.fileno())
        require((st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
                (change.st_size, change.st_mtime_ns, change.st_ctime_ns), "snapshot changed")
    require(base64.b64encode(md5.digest()) == b"OIg3IgSPOyyRVGHp/P1MLA==", "GCS generation MD5")
    return json.loads(raw), sha.hexdigest(), (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def run(scratch, receipts):
    budget = admitted(scratch, receipts)
    # PID 1 also owns the cgroup lifetime. Interrupt blocking IPC in Python so
    # the context manager can reap the exact child if a worker stops replying.
    def expired(_signum, _frame):
        raise TimeoutError("reference attempt exceeded 24 hours")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(24 * 3600)
    manifest, sha, identity = lookup_inputs()
    result = {}
    for version, end in ((8, END), (6, DOWNSTREAM)):
        started = time.monotonic()
        with worker(version) as session:
            session.initialize(SNAPSHOT, GENESIS, scratch, BOOT, ARCHIVE_HASH)
            boot = session.checkpoint(BOOT)
            require(boot["write_count"] == 0 and same_state(boot, manifest["bootstrap"]),
                    "native bootstrap consensus tuple")
            saved = {BOOT: boot}
            last = BOOT
            transactions = present = 0
            for ep in range(157, end // 432000 + 1):
                for slot, parent, entries in blocks(ep, last + 1, end):
                    require(parent == last, f"CAR ancestry gap at {slot} (parent {parent}, previous {last})")
                    session.process(slot, entries)
                    transactions += sum(len(row[2]) for row in entries)
                    present += 1
                    if slot in (ROOT, END, NEXT, DOWNSTREAM):
                        state = session.checkpoint(slot)
                        require(state["transaction_count"] == boot["transaction_count"] + session.successful,
                                "native cumulative transaction count")
                        require(state["last_blockhash"] == base58(entries[-1][1]), "checkpoint PoH")
                        if slot == ROOT:
                            require(same_state(state, manifest["terminal"]), "canonical intermediate root")
                        elif slot == END:
                            require(state["bank_hash"] == TERMINAL_BANK and
                                    state["last_blockhash"] == TERMINAL_POH, "signed terminal bank")
                            if version == 6:
                                require(same_state(state, result[8]["states"][END]), "cross-runtime terminal")
                        elif slot == NEXT:
                            require(state["bank_hash"] == SUCCESSOR_BANK and
                                    state["last_blockhash"] == SUCCESSOR_POH, "signed successor bank")
                        elif slot == DOWNSTREAM:
                            require(state["accounts_hash"] == DOWNSTREAM_ACCOUNTS, "downstream canonical root")
                        saved[slot] = state
                    last = slot
                    if present % 256 == 0:
                        print(json.dumps(dict(time=utc(), version=version, slot=last, blocks=present,
                                              transactions=transactions)), flush=True)
            required = {BOOT, ROOT, END} | ({NEXT, DOWNSTREAM} if version == 6 else set())
            require(last == end and set(saved) == required, "missing target bank")
        st = SNAPSHOT.stat()
        require(identity == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns),
                "bootstrap identity changed")
        require(not any(p.name != "lost+found" for p in scratch.iterdir()), "native scratch did not drain")
        result[version] = dict(states=saved, blocks=present, transactions=transactions,
                               successful_transactions=session.successful,
                               source_sha256=sha, elapsed_seconds=time.monotonic()-started,
                               runtime=f"solana-v1.5.{version}", completed_at=utc())
        immutable_json(receipts / f"v1.5.{version}.json", result[version])
    immutable_json(receipts / "comparison.json",
                   dict(schema="horizon-private-epoch157-terminal-reference-v1",
                        terminal=result[6]["states"][END], verified_downstream=result[6]["states"][DOWNSTREAM],
                        snapshot_sha256=sha, envelope=budget, paths=["v1.5.8.json","v1.5.6.json"],
                        accounts_hash_source="computed by two historical runtimes from a shared canonical bootstrap",
                        independently_published_terminal_accounts_hash=False, production_admission=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("probe")
    launch = sub.add_parser("replay")
    launch.add_argument("scratch", type=Path)
    launch.add_argument("receipts", type=Path)
    args = parser.parse_args()
    if args.command == "probe":
        print(json.dumps(source_probe(), sort_keys=True, indent=2))
    else:
        run(args.scratch, args.receipts)
