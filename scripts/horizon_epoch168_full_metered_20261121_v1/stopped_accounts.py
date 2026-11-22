#!/usr/bin/python3 -IB
"""Inventory the stopped full-metered 168 AccountsDb and identify its retained restart inputs."""
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from production import PAYLOAD_SHA, PKG, RUN, STATE, TREE, complete_offline, need, verified


PROOFS = TREE.parent / "four-prefix-recovery-20261122"
IID = "9cebb1d022124fb08588e93e055d5446"


def identity(path):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode), f"wrong file: {path}")
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def accounts_inventory(target):
    """Validate the four-shard AppendVec layout and count allocated bytes, including directories."""
    directory = target.lstat()
    need(stat.S_ISDIR(directory.st_mode) and target.resolve(strict=True) == target, "accounts path changed")
    need(sorted(os.listdir(target)) == ["0", "1", "2", "3"], "unknown accounts shard")
    ledger = hashlib.sha256()
    files = 0
    allocated = directory.st_blocks * 512
    for shard in sorted(target.iterdir()):
        before = shard.lstat()
        need(stat.S_ISDIR(before.st_mode) and before.st_dev == directory.st_dev, "foreign shard")
        allocated += before.st_blocks * 512
        with os.scandir(shard) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                info = entry.stat(follow_symlinks=False)
                need(re.fullmatch(r"[0-9]+\.[0-9]+", entry.name) and stat.S_ISREG(info.st_mode)
                     and info.st_dev == directory.st_dev and info.st_nlink == 1,
                     f"unexpected AppendVec: {entry.path}")
                ledger.update(f"{shard.name}/{entry.name} {info.st_ino} {info.st_size} "
                              f"{info.st_blocks} {info.st_mtime_ns} {info.st_ctime_ns}\n".encode())
                allocated += info.st_blocks * 512
                files += 1
        after = shard.lstat()
        need((before.st_ino, before.st_ctime_ns) == (after.st_ino, after.st_ctime_ns), "shard changed")
    need(files > 0 and target.lstat().st_ctime_ns == directory.st_ctime_ns, "empty or changed AccountsDb")
    return dict(path=str(target), device=directory.st_dev, inode=directory.st_ino, appendvecs=files,
                allocated_bytes=allocated, metadata_sha256=ledger.hexdigest())


def inspect():
    worker = verified(STATE / "FIRST_PROTECTED_WORKER.json",
                      "f0881354a940f74fff699c5de9d205c427a3d0414672ce41133e28a2bd0428c6")
    stop = verified(STATE / "guard-receipts/stop-completion.json",
                    "1fba7a686be4387737b8c7776a5ed92a59bff82c15ced77496e9214c94710f62")
    j = verified(PKG / "payload.json", PAYLOAD_SHA)
    partial = verified(PROOFS / "receipts/epoch-168.json",
                       "c1a93d6a62271731f85e684867d97606bb699b6a9cb8655abeecb0934fdb9825")
    recovery = verified(PROOFS / "cold-bootstrap-verification.json",
                        "63510d3ddf607d96ba9182163014234fc348b70448892db02466df2090de197e")
    origin, = [r for r in recovery["rows"] if r["epoch"] == 168]
    terminal = stop["terminal"]
    need(worker["producer_invocation_id"] == stop["producer_invocation_id"] == origin["producer_invocation"] == IID
         and terminal["active"] == "inactive" and terminal["pid"] == 0 and not stop["scratch_deleted"],
         "wrong stopped producer")
    cgroup = Path("/sys/fs/cgroup") / terminal["cgroup"].lstrip("/")
    need(not cgroup.exists() or not (cgroup / "cgroup.procs").read_text().strip(), "original cgroup has members")
    boot = j["bootstrap_file"]
    for item in [boot, j["genesis"], j["retained_terminal_partial"], *[i["source"] for i in j["indexes"]]]:
        need(identity(Path(item["path"])) == item["identity"], "retained restart input changed: " + item["path"])
    need(origin["snapshot"]["identity"] == boot["identity"] and origin["snapshot"]["sha256"] == boot["sha256"]
         and not origin["suffix_boundary_match_available"] and j["environment"]["JETSTREAMER_LOAD_FROM_DIR"] == "0"
         and j["environment"]["JETSTREAMER_CLEAR_ACCOUNTS_ON_START"] == "true", "cold start not established")
    scratch = Path(worker["observer_row"]["scratch_path"])
    archive = scratch.parent / "archives/epoch-168.jet"
    need(scratch.is_relative_to(RUN) and str(archive) == partial["source"], "foreign archive")
    expected = partial["identity"]
    need(identity(archive) == [expected[k] for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")],
         "checksummed prefix changed")
    runtime, = scratch.glob(".historical-runtime/*/jetstreamer-historical-v1.5.6-*")
    need(sorted(os.listdir(runtime / "unpacked/snapshots")) == ["72575704", "status_cache"],
         "another Bank snapshot requires review")
    return dict(epoch=168, stopped_producer=IID, accounts=accounts_inventory(runtime / "accounts-state"),
                checked_prefix_bytes=partial["source_bytes"], last_complete_bucket_slot=partial["last_complete_bucket_slot"],
                prefix_sha256=partial["source_sha256"], bootstrap=boot, previous_native_controls=complete_offline(),
                restart_slot=72575704, root_checkpoint=j["root_checkpoint"]["slot"], whole_tree_cap=j["whole_root_cap"],
                source_retained=True, local_unlink_authorized=False, replay_admitted=False)


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2, sort_keys=True))
