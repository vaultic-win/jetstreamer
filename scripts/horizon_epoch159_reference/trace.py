#!/usr/bin/python3 -IB
"""Exercise the original epoch 159 native vote from a pinned snapshot and original entries."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source import BOOT, CONFIG, END, VOTE, VOTE_WIRE, original_blocks
from car import require
from native import base58, worker

SLOT_HASHES = bytes.fromhex("06a7d517192f0aafc6f265e3fb77cc7ada82c529d0be3b136e2d005520000000")
HOME = Path("/home/sol/.jetstreamer-private")
CHECKPOINTS = (68_687_999, 68_688_000, END)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record(path, data):
    with path.open("x") as out:
        json.dump(data, out, sort_keys=True, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inputs():
    identities = {}
    for name in ("bootstrap", "genesis"):
        row = CONFIG[name]
        path = Path(row["path"])
        require(path.resolve(strict=True) == path, "indirect trace input")
        with path.open("rb") as fp:
            before = os.fstat(fp.fileno())
            actual = hashlib.file_digest(fp, "sha256").hexdigest()
            after = os.fstat(fp.fileno())
            require(
                before.st_ctime_ns == after.st_ctime_ns
                and os.path.samestat(after, path.stat())
                and actual == row["sha256"],
                "trace input identity changed",
            )
            if name == "bootstrap":
                require(before.st_size == row["size"], "snapshot length")
            identities[name] = dict(
                path=str(path),
                sha256=actual,
                dev=after.st_dev,
                ino=after.st_ino,
                ctime_ns=after.st_ctime_ns,
                length=after.st_size,
            )
    return identities


def allocation(scratch, receipts):
    require(
        os.geteuid() != 0
        and receipts.is_relative_to(HOME)
        and os.stat(receipts).st_dev == HOME.stat().st_dev,
        "private receipt storage",
    )
    for path in (scratch, receipts):
        st = path.lstat()
        require(
            path.resolve(strict=True) == path
            and path.is_dir()
            and st.st_uid == os.getuid()
            and st.st_mode & 0o077 == 0
            and all(path == scratch and x.name == "lost+found" for x in path.iterdir()),
            "trace directories must be empty and private",
        )
    device, typ = subprocess.check_output(
        ["findmnt", "-n", "-o", "SOURCE,FSTYPE", "-T", scratch], text=True
    ).split()
    require(
        scratch.is_mount()
        and typ == "ext4"
        and device.startswith("/dev/loop")
        and device[9:].isdecimal(),
        "bounded scratch mount",
    )
    backing = Path((Path("/sys/block") / Path(device).name / "loop/backing_file").read_text().strip())
    sb = backing.stat()
    v = os.statvfs(scratch)
    require(
        backing.is_relative_to(HOME)
        and not os.access(backing, os.W_OK)
        and sb.st_dev == HOME.stat().st_dev
        and sb.st_size == 24 << 30
        and sb.st_blocks * 512 >= sb.st_size
        and v.f_bavail * v.f_frsize >= 22 << 30
        and v.f_favail >= 500000,
        "scratch booking or inode capacity",
    )
    cg = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().removeprefix(
        "0::"
    ).lstrip("/")
    quota, period = (cg / "cpu.max").read_text().split()
    require(
        int(quota) == 2 * int(period)
        and int((cg / "memory.max").read_text()) == 48 << 30
        and int((cg / "memory.swap.max").read_text()) == 0,
        "trace service resource booking",
    )
    return dict(
        cgroup=str(cg),
        scratch=str(scratch),
        home_backing=str(backing),
        home_bytes=sb.st_size,
        memory_bytes=48 << 30,
        cpu_cores=2,
        swap=0,
    )


def trace(scratch, receipts):
    booking = allocation(scratch, receipts)
    source = inputs()
    incident = CONFIG["bootstrap"]["checkpoint"]
    started = time.monotonic()
    record(
        receipts / "start.json",
        dict(
            started=utc(),
            booking=booking,
            source=source,
            intended_slots=[BOOT + 1, END],
            qualified_original_windows=CONFIG["car_windows"],
        ),
    )
    receipt = dict(
        bootstrap=None,
        states={},
        slot_hashes={},
        vote=None,
        blocks=0,
        entries=0,
        transactions=0,
        source_windows=[],
        last_complete=None,
        signed_mismatches=[],
        complete=False,
    )

    def capture_write(frame, version, pubkey, data):
        if pubkey != SLOT_HASHES or frame not in (*CHECKPOINTS, 68_687_998):
            return
        require(len(data) == 20488 and int.from_bytes(data[:8], "little") == 512, "SlotHashes decode")
        pairs = [
            (int.from_bytes(data[i : i + 8], "little"), base58(data[i + 8 : i + 40]))
            for i in range(8, len(data), 40)
        ]
        require(all(a[0] > b[0] for a, b in zip(pairs, pairs[1:])), "SlotHashes unordered")
        expected = CONFIG["slothashes"].get(str(frame))
        actual = hashlib.sha256(data).hexdigest()
        filename = f"slot-hashes-{frame}-{version}.json"
        record(
            receipts / filename, dict(slot=frame, write_version=version, sha256=actual, entries=pairs)
        )
        receipt["slot_hashes"][str(frame)] = dict(
            write_version=version,
            tip=pairs[0],
            sha256=actual,
            expected=expected,
            evidence=filename,
            signed_mismatches=[
                dict(slot=n, observed=h, signed=CONFIG["signed_bank_hashes"][str(n)])
                for n, h in pairs
                if str(n) in CONFIG["signed_bank_hashes"] and h != CONFIG["signed_bank_hashes"][str(n)]
            ],
            expected_table_match=expected == actual if expected else None,
        )

    def timeout(signum, frame):
        raise TimeoutError("bounded reference expired")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(2 * 3600)
    try:
        with worker(6) as session:
            session.initialize(
                Path(source["bootstrap"]["path"]),
                Path(source["genesis"]["path"]),
                scratch,
                BOOT,
                incident["accounts_hash"],
            )
            state = session.checkpoint(BOOT)
            receipt["bootstrap"] = state
            require(
                all(
                    state[k] == incident[k]
                    for k in (
                        "slot",
                        "bank_hash",
                        "accounts_hash",
                        "last_blockhash",
                        "capitalization",
                        "tick_height",
                    )
                )
                and incident["transactions"] == state["transaction_count"],
                "restored consensus checkpoint differs",
            )
            record(receipts / "bootstrap.json", state)
            for slot, parent, entries in original_blocks(
                CONFIG["car_windows"], receipt["source_windows"]
            ):
                target_ordinal = 0

                def capture_outcome(tx, status, fee):
                    nonlocal target_ordinal
                    if tx == VOTE_WIRE:
                        require(
                            slot == END
                            and target_ordinal == VOTE["ordinal"]
                            and receipt["vote"] is None,
                            "wrong observed vote position",
                        )
                        receipt["vote"] = dict(
                            slot=slot,
                            entry_index=VOTE["entry_index"],
                            transaction_in_entry=VOTE["transaction_in_entry"],
                            ordinal=target_ordinal,
                            signature=base58(tx[1:65]),
                            status=status,
                            fee=fee,
                            accepted=status is None,
                        )
                        record(receipts / "vote.json", receipt["vote"])
                    target_ordinal += 1

                session.process(slot, entries, capture_outcome if slot == END else None, capture_write)
                receipt["blocks"] += 1
                receipt["entries"] += len(entries)
                receipt["transactions"] += sum(len(row[2]) for row in entries)
                receipt["last_complete"] = slot
                if slot in CHECKPOINTS:
                    state = session.checkpoint(slot, capture_write)
                    require(
                        state["last_blockhash"] == base58(entries[-1][1])
                        and state["transaction_count"] == incident["transactions"] + session.successful,
                        "native checkpoint output mismatch",
                    )
                    receipt["states"][str(slot)] = state
                    signed = CONFIG["signed_bank_hashes"][str(slot)]
                    if state["bank_hash"] != signed:
                        receipt["signed_mismatches"].append(
                            dict(slot=slot, observed=state["bank_hash"], signed=signed)
                        )
                    record(receipts / f"checkpoint-{slot}.json", state)
                if receipt["blocks"] % 32 == 0:
                    print(
                        f"slot {slot} blocks {receipt['blocks']} transactions {receipt['transactions']}",
                        flush=True,
                    )
        require(
            receipt["last_complete"] == END
            and receipt["vote"] is not None
            and all(receipt[k] == v for k, v in CONFIG["source_counters"].items()),
            "incomplete bounded trace",
        )
        require(
            all(s in receipt["slot_hashes"] for s in CONFIG["slothashes"]),
            "missing worker SlotHashes writes",
        )
        receipt["complete"] = True
        receipt["canonical_checks_passed"] = (
            receipt["vote"]["accepted"]
            and not receipt["signed_mismatches"]
            and all(receipt["slot_hashes"][s]["expected_table_match"] for s in CONFIG["slothashes"])
        )
    except BaseException as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        signal.alarm(0)
        receipt.update(finished=utc(), elapsed_seconds=time.monotonic() - started)
        record(receipts / "outcome.json", receipt)
    require(
        receipt["canonical_checks_passed"],
        "actual native Bank/vote disagrees; see retained checkpoints and outcome",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check-source")
    run = sub.add_parser("replay")
    run.add_argument("scratch", type=Path)
    run.add_argument("receipts", type=Path)
    args = parser.parse_args()
    if args.action == "check-source":
        counts = dict(blocks=0, entries=0, transactions=0)
        for _, _, entries in original_blocks(CONFIG["car_windows"]):
            counts["blocks"] += 1
            counts["entries"] += len(entries)
            counts["transactions"] += sum(len(row[2]) for row in entries)
        require(counts == CONFIG["source_counters"], "source totals disagree")
        print(json.dumps(counts))
    else:
        trace(args.scratch, args.receipts)


if __name__ == "__main__":
    main()
