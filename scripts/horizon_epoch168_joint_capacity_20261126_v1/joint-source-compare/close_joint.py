"""Capture the enrolled Anza joint checkpoint at its native process exit."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-joint-checkpoint-reduced-run-20261126-v1")
HELPER = STATE / "lineage-tools-20261127-v1/epoch168_lineage_handoff.py"
GUARD = "horizon-guard-168-joint-checkpoint-reduced-20261126-v1.service"
TIMER = GUARD.removesuffix(".service") + ".timer"
TIMER_ID = "e60d22e2caa241d48ac9d738f42515b1"
ENROLLMENT_SHA = "6adcac735946316de1c6cf4b8bf112bab8c78e11119af3ac899074e24a5e4e7e"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"
ROOT_HASH = "AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R"


def require(ok, explanation):
    if not ok:
        raise ValueError(explanation)


def helper():
    raw = HELPER.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == "22fd7d396afc0c20375d9dfde50ffbbebf19cacc91a53ba83e5e2fbcda730385",
            "unexpected deployed journal helper")
    spec = importlib.util.spec_from_file_location("joint_lineage", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unit_properties(unit):
    result = subprocess.run(["systemctl", "show", unit, "-p", "Id,InvocationID,MainPID,ControlPID,ActiveState,Job"],
                            capture_output=True, text=True)
    require(result.returncode in (0, 4), "cannot inspect " + unit)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines())
    require(values["Id"] == unit, "wrong service identity")
    return values


def idle(unit):
    props = unit_properties(unit)
    path = Path("/sys/fs/cgroup/system.slice") / unit / "cgroup.procs"
    return (props["ActiveState"] in ("inactive", "failed") and not props["Job"]
            and all(props.get(key, "0") == "0" for key in ("MainPID", "ControlPID"))
            and (not path.exists() or not path.read_bytes().strip()))


def wait_for_exit(api, actor):
    pid = actor["pid"]
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        props = unit_properties(api.JOINT_UNIT)
        if props["InvocationID"] == api.JOINT_IID and props["MainPID"] == str(pid):
            start = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
            require(start == actor["start_ticks"], "producer PID was reused")
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            poller.poll()
        else:
            require(idle(api.JOINT_UNIT), "different producer occupies the joint unit")
    finally:
        os.close(fd)


def terminal_event(api, actor):
    for _ in range(60):
        rows = api.journal("_PID=1", "_UID=0", "UNIT=" + api.JOINT_UNIT, "INVOCATION_ID=" + api.JOINT_IID)
        exits = [row for row in rows if row.get("MESSAGE_ID") == api.SUCCESS
                 or (row.get("MESSAGE_ID") == FAILURE and row.get("COMMAND") == "ExecStart"
                     and int(row["EXIT_STATUS"]) != 0)]
        if exits and idle(api.JOINT_UNIT):
            require(len(exits) == 1 and exits[0]["_BOOT_ID"] == actor["boot_id"].replace("-", "")
                    and int(exits[0]["__REALTIME_TIMESTAMP"]) >= actor["ready_at"] * 1000000,
                    "unexpected or ambiguous native exit")
            return exits[0]
        time.sleep(1)
    raise ValueError("matching native exit and drained cgroup not observed")


def verified_checkpoint(api, enrollment):
    manifest_ref, manifest = api.bound_json(api.JOINT.with_suffix(".jet.segment.json"), 1001)
    terminal = manifest["terminal"]
    require((manifest["schema_version"], manifest["epoch"], manifest["output_slot_start"], manifest["output_slot_count"])
            == (1, 168, 72991437, 16393) and terminal["slot"] == 73007829 and terminal["slot_complete"] is True
            and terminal["accounts_hash"] == ROOT_HASH and manifest["bootstrap"]["slot"] == 72991436
            and manifest["worker_executable_sha256"] == "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541",
            "closed segment differs from the enrolled replay")
    log = enrollment["append_log"]
    with open(log["path"], "rb") as inp:
        info = os.fstat(inp.fileno())
        require((info.st_dev, info.st_ino) == (log["device"], log["inode"]), "producer log replaced")
        inp.seek(max(0, info.st_size - (8 << 20)))
        tail = inp.read().decode(errors="strict").splitlines()
    verified, = [line for line in tail if line.endswith("verified legacy accounts hash at slot 73007829")]
    checkpoint, = [line for line in tail if "historical checkpoint slot=73007829 " in line]
    values = dict(re.findall(r"(\w+)=(\w+)", checkpoint))
    for key, value in terminal.items():
        label = {"write_count":"writes", "transaction_count":"transactions", "slot_complete":"complete"}.get(key, key)
        require(values[label] == (str(value).lower() if isinstance(value, bool) else str(value)),
                "manifest differs from the native checkpoint at " + key)
    with api.JOINT.open("rb") as inp:
        info = os.fstat(inp.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 1001
                and api.JOINT.resolve(strict=True) == api.JOINT, "unexpected archive custody")
        sha = hashlib.file_digest(inp, "sha256").hexdigest()
        require(api.identity(info) == api.identity(os.fstat(inp.fileno())) == api.identity(api.JOINT.lstat())
                and sha == manifest["archive_sha256"], "closed archive readback differs")
    return dict(manifest=manifest_ref, verified_line=verified, checkpoint_line=checkpoint,
                archive_sha256=sha, archive_bytes=info.st_size, terminal_checkpoint=terminal)


def close(wait):
    api = helper()
    ref, enrolled = api.bound_json(STATE / "ACCOUNTING_ENROLLMENT.json")
    actor = enrolled["actor"]
    require(ref["sha256"] == ENROLLMENT_SHA and actor["invocation_id"] == api.JOINT_IID
            and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == actor["boot_id"],
            "wrong accounting enrollment or boot")
    output = STATE / "TERMINAL.json"
    if output.exists():
        _, existing = api.bound_json(output)
        require(existing["enrollment"] == ref and existing["producer_invocation_id"] == api.JOINT_IID
                and idle(api.JOINT_UNIT) and idle(TIMER) and idle(GUARD), "conflicting existing terminal")
        return
    if wait:
        wait_for_exit(api, actor)
    event = terminal_event(api, actor)
    timer = unit_properties(TIMER)
    if not idle(TIMER):
        require(timer["InvocationID"] == TIMER_ID, "different guard timer owns this slot")
        subprocess.run(["systemctl", "stop", TIMER], check=True)
    for _ in range(60):
        if idle(TIMER) and idle(GUARD):
            break
        time.sleep(1)
    require(idle(api.JOINT_UNIT) and idle(TIMER) and idle(GUARD), "producer or guard still has work")
    success = event["MESSAGE_ID"] == api.SUCCESS
    evidence = verified_checkpoint(api, enrolled) if success else {}
    api.store(output, dict(schema="horizon-epoch168-joint-reduced-terminal-v1", enrollment=ref,
                           producer_invocation_id=api.JOINT_IID, producer_pid=actor["pid"],
                           producer_start_ticks=actor["start_ticks"], pid1_terminal_event=event,
                           disposition="checkpoint-complete" if success else "failed", resource_credit_bytes=0,
                           private_output_preserved=True, archive_publication_authorized=False, remote_mutations=False,
                           independent_archive_scan_pending=True, **evidence))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", action="store_true", help="wait on the original producer pidfd")
    close(parser.parse_args().wait)
