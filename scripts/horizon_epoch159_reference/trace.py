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
import feature19
import feature156

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


def mounted_inputs(corrected=False, backport=False):
    import _cbor2
    import cbor2
    from native import DEPLOY

    require(os.geteuid() == 1001 and not os.getgroups(), "sandbox identity")
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    require(
        status["NoNewPrivs"].strip() == "1"
        and int(status["CapEff"].strip(), 16) == 0
        and int(status["CapBnd"].strip(), 16) == 0,
        "sandbox privilege drop",
    )
    deps = json.loads(Path(__file__).with_name("dependencies.json").read_bytes())
    seen = {}
    worker_ref = deps["worker"]
    expected_worker = DEPLOY / "jetstreamer-historical-worker-v1-5-6"
    if corrected:
        expected_worker = feature19.WORKER
        worker_ref = dict(path=str(feature19.WORKER), length=8732096, sha256=feature19.IMAGE)
    elif backport:
        expected_worker = feature156.WORKER
        worker_ref = feature156.worker_row()
    for row in [*deps["cbor2"], worker_ref]:
        p = Path(row["path"])
        st = p.stat()
        require(
            not os.access(p, os.W_OK)
            and st.st_size == row["length"]
            and hashlib.sha256(p.read_bytes()).hexdigest() == row["sha256"],
            "different service-visible native dependency",
        )
        seen[str(p)] = dict(dev=st.st_dev, ino=st.st_ino, sha256=row["sha256"])
    require(
        _cbor2.__file__ in seen
        and cbor2.__file__ in seen
        and cbor2.load is _cbor2.load
        and str(expected_worker) in seen,
        "native dependency resolution",
    )
    source = inputs()
    require(
        all(not os.access(v["path"], os.W_OK) for v in source.values()),
        "writable service input",
    )
    return dict(
        source=source,
        dependencies=seen,
        uid=os.geteuid(),
        gid=os.getegid(),
        caps=status["CapEff"].strip(),
        no_new_privs=status["NoNewPrivs"].strip(),
    )


def allocation(scratch, receipts, corrected=False, backport=False):
    require(
        os.geteuid() == 1001 and (scratch, receipts) == (Path("/work"), Path("/evidence")),
        "wrong service user or mounts",
    )
    runtime_name = "epoch159-bounded-reference-20261123-v1"
    if corrected:
        runtime_name = feature19.RUNTIME
    elif backport:
        runtime_name = feature156.RUNTIME
    backing = {}
    for path, size, name in (
        (scratch, 24 << 30, "scratch.ext4"),
        (receipts, 8 << 20, "evidence.ext4"),
    ):
        st = path.lstat()
        require(
            path.is_mount()
            and path.is_dir()
            and st.st_uid == os.getuid()
            and st.st_mode & 0o077 == 0
            and all(f.name == "lost+found" for f in path.iterdir()),
            "unclean service mount",
        )
        devsys = Path("/sys/dev/block") / f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
        image = (devsys / "loop/backing_file").read_text().strip()
        allowed = [
            str(
                root
                / runtime_name
                / "attempt-v1"
                / name
            )
            for root in (
                HOME / "horizon-root-runtime-data",
                Path("/var/lib/jetstreamer/horizon_runtime_data"),
            )
        ]
        mount = subprocess.check_output(
            ["findmnt", "-n", "-o", "FSTYPE,OPTIONS", "-T", path], text=True
        ).split()
        require(
            image in allowed
            and int((devsys / "size").read_text()) * 512 == size
            and mount[0] == "ext4"
            and {"nodev", "nosuid", "noexec"} <= set(mount[1].split(",")),
            "wrong paid loop mount",
        )
        backing[str(path)] = image
    v = os.statvfs(scratch)
    require(v.f_bavail * v.f_frsize >= 22 << 30 and v.f_favail >= 500000, "scratch capacity")
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
        home_backing=backing,
        home_bytes=(24 << 30) + (8 << 20),
        memory_bytes=48 << 30,
        cpu_cores=2,
        swap=0,
    )


def trace(scratch, receipts, corrected=False, backport=False):
    booking = allocation(scratch, receipts, corrected, backport)
    mounted = mounted_inputs(corrected, backport)
    source = mounted["source"]
    incident = CONFIG["bootstrap"]["checkpoint"]
    started = time.monotonic()
    record(
        receipts / "start.json",
        dict(
            started=utc(),
            booking=booking,
            source=source,
            dependencies=mounted["dependencies"],
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
        feature_writes=[],
    )

    write_chain = hashlib.sha256()
    write_count = 0

    def capture_feature(*args):
        nonlocal write_count
        feature19.observe(receipt["feature_writes"], *args)
        if backport and args[0] == BOOT + 1:
            # Bind each first-child native write version, key and stored account hash in wire order.
            write_chain.update(args[1].to_bytes(8, "little") + args[2] + args[-1])
            write_count += 1

    on_account = capture_feature if corrected or backport else None

    def capture_write(frame, version, pubkey, data):
        if pubkey != SLOT_HASHES or frame not in (*CHECKPOINTS, 68_687_998):
            return
        require(
            len(data) == 20488 and int.from_bytes(data[:8], "little") == 512,
            "SlotHashes decode",
        )
        pairs = [
            (int.from_bytes(data[i : i + 8], "little"), base58(data[i + 8 : i + 40]))
            for i in range(8, len(data), 40)
        ]
        require(all(a[0] > b[0] for a, b in zip(pairs, pairs[1:])), "SlotHashes unordered")
        expected = CONFIG["slothashes"].get(str(frame))
        actual = hashlib.sha256(data).hexdigest()
        filename = f"slot-hashes-{frame}-{version}.json"
        record(
            receipts / filename,
            dict(slot=frame, write_version=version, sha256=actual, entries=pairs),
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
        version = 19 if corrected else 6
        image = (feature19.WORKER, feature19.IMAGE, feature19.REVISION) if corrected else None
        if backport:
            image = (feature156.WORKER, feature156.worker_row()["sha256"], feature156.spec()["solana"])
        with worker(version, image=image) as session:
            native = Path("/proc") / str(session.proc.pid)

            def identity(proc):
                exe = (proc / "exe").stat()
                ids = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
                return dict(
                    pid=int(proc.resolve().name),
                    parent=int(ids[1]),
                    start_ticks=int(ids[19]),
                    exe=os.readlink(proc / "exe"),
                    dev=exe.st_dev,
                    ino=exe.st_ino,
                    comm=(proc / "comm").read_text().strip(),
                    cgroup=(proc / "cgroup").read_text().strip(),
                )

            driver = identity(Path("/proc/self"))
            child = identity(native)
            require(
                child["parent"] == driver["pid"]
                and child["cgroup"] == driver["cgroup"]
                and child["exe"].endswith(f"/jetstreamer-historical-worker-v1-5-{version}")
                and (image is None or child["exe"] == str(image[0])),
                "unexpected original worker or parent",
            )
            record(
                receipts / "hello.json",
                dict(
                    invocation_id=os.environ["INVOCATION_ID"],
                    driver=driver,
                    worker=child,
                    protocol=5,
                ),
            )
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
            canonical_outcomes = feature156.spec()["canonical_transaction_outcomes"] if backport else {}
            for slot, parent, entries in original_blocks(
                CONFIG["car_windows"], receipt["source_windows"]
            ):
                target_ordinal = 0
                tx_rows = []
                audit_tx = backport and str(slot) in canonical_outcomes

                def capture_outcome(tx, status, fee, slot=slot):
                    nonlocal target_ordinal
                    if audit_tx:
                        tx_rows.append([tx[1:65].hex(), status, fee])
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

                session.process(
                    slot,
                    entries,
                    capture_outcome if slot == END or audit_tx else None,
                    capture_write,
                    on_account,
                )
                receipt["blocks"] += 1
                receipt["entries"] += len(entries)
                receipt["transactions"] += sum(len(row[2]) for row in entries)
                receipt["last_complete"] = slot
                if audit_tx:
                    signed_digest = feature156.transaction_digest(tx_rows)
                    matched = (len(tx_rows) == canonical_outcomes[str(slot)]["transactions"]
                               and signed_digest == canonical_outcomes[str(slot)]["signed_outcomes_sha256"])
                    record(receipts / f"transactions-{slot}.json", dict(rows=tx_rows, sha256=signed_digest, matched=matched))
                    receipt.setdefault("canonical_transactions", {})[str(slot)] = matched
                if slot in CHECKPOINTS or (backport and slot == BOOT + 1):
                    state = session.checkpoint(slot, capture_write, on_account)
                    require(
                        state["last_blockhash"] == base58(entries[-1][1])
                        and state["transaction_count"] == incident["transactions"] + session.successful,
                        "native checkpoint output mismatch",
                    )
                    receipt["states"][str(slot)] = state
                    record(receipts / f"checkpoint-{slot}.json", state)
                    if backport and slot == BOOT + 1:
                        record(receipts / f"first-writes-{slot}.json", dict(count=write_count, sha256=write_chain.hexdigest()))
                    if backport and slot <= 68_687_999:
                        feature156.check_checkpoint(state)
                        if slot == BOOT + 1:
                            require(receipt["canonical_transactions"][str(slot)], "first-child native outcomes differ")
                    signed_hashes = feature156.spec()["signed_checkpoints"] if backport else CONFIG["signed_bank_hashes"]
                    signed = signed_hashes[str(slot)]
                    if state["bank_hash"] != signed:
                        receipt["signed_mismatches"].append(
                            dict(slot=slot, observed=state["bank_hash"], signed=signed)
                        )
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
            and (not (corrected or backport) or feature19.accepted(receipt["feature_writes"]))
            and (not backport or receipt.get("canonical_transactions") == {s: True for s in canonical_outcomes})
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--feature19", action="store_true")
    mode.add_argument("--feature156", action="store_true")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check-source")
    sub.add_parser("check-mounted-inputs")
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
    elif args.action == "check-mounted-inputs":
        print(json.dumps(mounted_inputs(args.feature19, args.feature156), sort_keys=True))
    else:
        trace(args.scratch, args.receipts, args.feature19, args.feature156)


if __name__ == "__main__":
    main()
