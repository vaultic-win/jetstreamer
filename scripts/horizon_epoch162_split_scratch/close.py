"""Read the retained interval without a second archive copy after the particular producer drains."""

import argparse
import fcntl
import json
import os
import runpy
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
l = SimpleNamespace(**runpy.run_path(str(HERE / "layout.py")))
inner_alias = Path("/run/horizon-162-split-readback")
archive = l.RUN / "ledger/epoch-162.diagnostic.jet"


def read_inside():
    mount = json.loads(
        subprocess.check_output(["findmnt", "-M", str(l.RUN), "-J", "-o", "FSTYPE,VFS-OPTIONS,MAJ:MIN"], text=True)
    )["filesystems"][0]
    l.need(
        mount["fstype"] == "ext4"
        and mount["maj:min"].split(":")[0] == "7"
        and "ro" in mount["vfs-options"].split(",")
        and os.getuid() == 1001
        and os.getgid() == 1003,
        "unprotected readback mount",
    )
    before = l.identity(archive)
    l.need(stat.S_ISREG(archive.lstat().st_mode) and 0 < before[2] <= l.HOME_IMAGE, "no bounded private archive")
    check = runpy.run_path(str(HERE / "stock_prefix.py"))
    stock = check["stream"](check["BASE"], stock=True)
    l.need(stock["file_bytes"] == stock["complete_bucket_end"], "stock reference changed")
    candidate = check["stream"](archive)
    check["check"](stock, candidate)
    checksum = l.digest(archive)
    l.need(l.identity(archive) == before, "private archive changed during readback")
    print(
        json.dumps(
            dict(
                bytes=before[2],
                sha256=checksum,
                first_bucket=stock["encoded_slot_stream_sha256"],
                matching_slots=[stock["first"], stock["last"]],
                reader_invocation=os.environ["INVOCATION_ID"],
                mount=mount,
                kernel_backing=Path("/sys/dev/block", mount["maj:min"], "loop", "backing_file").read_text().strip(),
            )
        ),
        flush=True,
    )


def close():
    status = SimpleNamespace(**runpy.run_path(str(HERE / "status162.py")))
    status.api()
    held, held_ref = l.pinned(l.DATA / "HELD_OWNER.json")
    props = l.manager(l.UNIT)
    l.need(
        props["ActiveState"] in ("inactive", "failed")
        and props["MainPID"] == "0"
        and not props["Job"]
        and props["InvocationID"] in ("", held["producer_invocation_id"])
        and not l.CGROUP.exists(),
        "producer has not drained",
    )
    end = status.native_end(l, held)
    terminal = l.DATA / "TERMINAL.json"
    if terminal.exists():
        result, ref = l.pinned(terminal)
        l.need(
            result["held"] == held_ref and result["pid1"] == end and result["image"] == l.identity(l.IMAGE)[:3],
            "different previously recorded terminal",
        )
        return ref
    timer = l.manager(l.TIMER)
    if timer["ActiveState"] == "active":
        l.need(timer["InvocationID"] == held["guard_timer_invocation_id"], "foreign guard")
        subprocess.run(["systemctl", "stop", l.TIMER], check=True)
    l.need(
        l.manager(l.TIMER)["ActiveState"] in ("inactive", "failed")
        and l.manager(l.TIMER.replace(".timer", ".service"))["ActiveState"] in ("inactive", "failed"),
        "guard has not drained",
    )
    image = l.identity(l.IMAGE)[:3]
    l.need(image == held["mounts"]["image"], "different retained disk")
    result = dict(
        held=held_ref,
        pid1=end,
        image=image,
        image_path=str(l.IMAGE),
        canonical_writes=False,
        complete_epoch=False,
        private_checkpoint_matched=False,
        resource_credit_bytes=0,
    )
    samples = sorted(l.GUARDS.glob("sample-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    for path in samples:
        sample, sref = l.pinned(path)
        if sample["producer_invocation_id"] != held["producer_invocation_id"]:
            continue
        l.need(
            sample["guard_sha256"] == l.GUARD_SHA
            and sample["producer"]["pid"] == held["producer_pid"]
            and sample["plan_sha256"] == held["guard_plan"]["sha256"],
            "terminal guard changed",
        )
        if sample["trip_reason"]:
            result.update(disposition="guard-stopped", trip=sample["trip_reason"], guard=sref)
            return l.save(terminal, result)
    if end["MESSAGE_ID"] == status.SUCCESS:
        if not (l.DATA / "GRANT.json").exists():
            l.need(not l.ALLOW.exists(), "guarded payload was released without a grant")
            result.update(disposition="closed-before-release")
            return l.save(terminal, result)
        release, ref = l.pinned(l.DATA / "GRANT.json")
        l.need(
            release["held"] == held_ref and l.ALLOW.read_bytes() == held["producer_invocation_id"].encode(),
            "different private release",
        )
        checker = runpy.run_path(str(HERE / "terminal_bank.py"))
        checker["reference"]()
        journal = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--no-pager",
                "-q",
                "-o",
                "json",
                "_BOOT_ID=" + held["boot_id"].replace("-", ""),
                "_SYSTEMD_UNIT=" + l.UNIT,
                "_SYSTEMD_INVOCATION_ID=" + held["producer_invocation_id"],
                "_PID=" + str(held["producer_pid"]),
                "--grep=historical checkpoint slot=69991076 ",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        l.need(journal.returncode in (0, 1) and not journal.stderr.strip(), "unable to read native terminal journal")
        rows = [json.loads(line) for line in journal.stdout.splitlines()]
        try:
            witness = checker["compare"](rows, held["producer_invocation_id"], held["producer_pid"])
        except ValueError as error:
            result.update(
                disposition="closed-without-matching-checkpoint",
                terminal_journal_rows=rows,
                detail=str(error),
                grant=ref,
            )
            return l.save(terminal, result)
        unit = f"horizon-162-split-readback-{time.time_ns()}.service"
        args = [
            "systemd-run",
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--service-type=exec",
            "--unit=" + unit,
            "--property=User=sol",
            "--property=Group=horizon",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=read-only",
            "--property=PrivateNetwork=yes",
            "--property=PrivateDevices=yes",
            "--property=NoNewPrivileges=yes",
            "--property=MemoryMax=512M",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%",
            "--property=TasksMax=32",
            f"--property=MountImages={l.IMAGE}:{l.RUN}:ro,noload,nosuid,nodev",
            f"--property=BindReadOnlyPaths={l.PKG}:{inner_alias}",
            "--",
            "/usr/bin/python3",
            "-IB",
            str(inner_alias / "close.py"),
            "inside",
        ]
        # The producer's 62-GiB/2-CPU booking remains retained through this 512-MiB reader.
        read = json.loads(subprocess.check_output(args, text=True, timeout=900))
        backing = Path(read["kernel_backing"])
        l.need(
            any(p.is_file() and p.samefile(l.IMAGE) for p in (backing, Path("/home/sol") / backing.relative_to("/")))
            and l.identity(l.IMAGE)[:3] == image,
            "different retained source during readback",
        )
        result.update(
            grant=ref,
            terminal_bank=witness,
            archive=read,
            private_checkpoint_matched=True,
            whole_archive_playback=False,
        )
    return l.save(terminal, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("phase", choices=["close", "inside"])
    if parser.parse_args().phase == "inside":
        read_inside()
    else:
        with Path("/run/horizon-epoch171-to136-g1.operation.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(json.dumps(close(), indent=2))
