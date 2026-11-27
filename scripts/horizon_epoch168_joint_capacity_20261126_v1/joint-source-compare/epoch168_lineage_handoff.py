#!/usr/bin/python3
"""Prepare and capture the epoch 168 comparison under the operator's own control."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import uuid

STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-joint-checkpoint-reduced-run-20261126-v1")
HOME = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1")
JOINT = HOME / "joint-checkpoint-reduced-20261126-v1/output/epoch-168-joint-checkpoints.jet"
RETRY4 = HOME / "cold-retry4-20261123/private/destination-ab320aeb1bd39ca9218ae95ef9e9b04e92f493e106c9a0e0b70582f6f568f51e/work/root-cohort-168-168/run-916123-1795399774038214572/archives/epoch-168.jet"
RETRY6 = HOME / "cold-retry6-20261126/output/epoch-168-tail.jet"
COMPARATOR = STATE / "continuity-tools/horizon-168-joint-compare"
COMPARATOR_SHA = "bfe14ac703ed4f5e256fab9d6a24526f1540cdd5bda1bd544ab62b70643deed4"
COMPARATOR_SEAL_SHA = "55b98899587fc5409787cc83981810cc1266d396918906d445a3ceedb2a35c8e"
SELECTOR_STATE = STATE.parent / "epoch168-retry4-selected-prefix-20261127-v1"
SELECTOR_IID = "3398149c02ad460d98ab1ec8f656f55e"
SELECTOR_UNIT = "horizon-168-retry4-selected-prefix-20261127-v1.service"
ACTIVE_SHA = "f32a20461b7e4c524ffbb6d7de86288516114c2bea6020c710ca0642e2ba1b26"
TOOLS = SELECTOR_STATE / "tools"
CHECKER = TOOLS / "horizon-168-joint-lineage"
CHECKER_SHA = "fe627e54f0bae428f37b9ba54db2037d3dcb47e96733a3ee4c5e9c74e9279920"
CHECKER_SEAL_SHA = "6e5959fc84c1abc37817d13d5f69fd995e25ecfecce7dd4683653ca6adb60292"
JOINT_IID = "31c1503cecaf4edbb9a78a0c19c0ac9d"
JOINT_UNIT = "horizon-qualify-168-joint-checkpoint-reduced-20261126-v1.service"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
MAX_METADATA = 1 << 20
LABELS = ("predecessor_overlap", "successor_overlap", "comparison_complete")


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns,
            meta.st_ctime_ns, meta.st_uid, meta.st_mode, meta.st_nlink)


def bound(path, owner, limit=MAX_METADATA):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, f"indirect path {path}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as handle:
        before = os.fstat(handle.fileno())
        need(
            stat.S_ISREG(before.st_mode) and before.st_uid == owner
            and before.st_nlink == 1 and before.st_mode & 0o022 == 0 and before.st_size <= limit,
            f"untrusted file {path}",
        )
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    need(identity(before) == identity(after) and len(data) == before.st_size, f"changed file {path}")
    need(identity(path.lstat()) == identity(after), f"replaced file {path}")
    return {"path": str(path), "sha256": sha(data)}, data


def bound_json(path, owner=0):
    ref, data = bound(path, owner)
    return ref, json.loads(data)


def store(path, record):
    path = Path(path)
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, f"indirect output {path}")
    parent = path.parent.stat()
    need(parent.st_uid == 0 and parent.st_mode & 0o022 == 0, f"untrusted output directory {path.parent}")
    if path.exists():
        prior, prior_data = bound(path, 0)
        need(prior_data == data, f"existing evidence differs at {path}")
        return prior
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        tmp = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), 0o400)
            os.fsync(handle.fileno())
            os.link(tmp, path)
        finally:
            tmp.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(path), "sha256": sha(data)}


def terminal_ok(row, unit, iid):
    return all(row.get(k) == v for k, v in {
        "_PID": "1", "_UID": "0", "UNIT": unit, "INVOCATION_ID": iid,
        "MESSAGE_ID": SUCCESS,
    }.items())


def closed_inputs():
    terminal_ref, terminal = bound_json(STATE / "TERMINAL.json")
    end = terminal["pid1_terminal_event"]
    need(
        terminal["schema"] == "horizon-epoch168-joint-reduced-terminal-v1"
        and terminal["disposition"] == "checkpoint-complete"
        and terminal["producer_invocation_id"] == JOINT_IID
        and terminal["producer_pid"] == 3932422 and terminal["producer_start_ticks"] == 408835521
        and terminal["private_output_preserved"] is True and terminal_ok(end, JOINT_UNIT, JOINT_IID),
        "joint producer does not have its clean checkpoint-complete receipt",
    )
    manifest_ref, manifest = bound_json(JOINT.with_suffix(".jet.segment.json"), 1001)
    digest = manifest["archive_sha256"]
    need(
        manifest["epoch"] == 168 and manifest["schema_version"] == 1
        and manifest["output_slot_start"] == 72991437 and manifest["output_slot_count"] == 16393
        and manifest["terminal"]["slot"] == 73007829 and manifest["terminal"]["slot_complete"] is True
        and manifest["terminal"]["accounts_hash"] == "AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R"
        and re.fullmatch(r"(?!0{64})[0-9a-f]{64}", digest),
        "closed joint manifest differs from the expected root",
    )
    return terminal_ref, manifest_ref, digest, int(end["__REALTIME_TIMESTAMP"])


def launch_record(unit):
    terminal_ref, manifest_ref, digest, end_time = closed_inputs()
    exe_ref, _ = bound(COMPARATOR, 0, 16 << 20)
    seal_ref, seal = bound_json(COMPARATOR.parent / "deployment-seal-receipt.json")
    need(
        exe_ref["sha256"] == COMPARATOR_SHA and seal_ref["sha256"] == COMPARATOR_SEAL_SHA
        and any(m["name"] == COMPARATOR.name and m["sha256"] == COMPARATOR_SHA and m["mode"] == "0555"
                for m in seal["members"])
        and stat.S_IMODE(COMPARATOR.stat().st_mode) == 0o555,
        "sealed comparator bytes or package differ",
    )
    return {
        "schema": "horizon-epoch168-private-comparison-launch-v1",
        "unit": unit, "uid": "0", "argv": [str(COMPARATOR), "--compare-joint", digest],
        "executable_sha256": COMPARATOR_SHA, "joint_manifest": manifest_ref,
        "joint_terminal": terminal_ref, "joint_terminal_time_us": end_time,
        "deployment_seal": seal_ref,
        "sources": {
            "joint": {"path": str(JOINT), "sha256": digest},
            "retry4": {"path": str(RETRY4), "sha256": "cdde7f4da26d0d608f9546883aba787c903e093fc800bd570288e803c0aefc3d"},
            "retry6": {"path": str(RETRY6), "sha256": "4a3356c72e2216a8f0a76d0f4ce3d9272d98dadf66deba46e40fa8396e170cea"},
        },
    }


def prepare(path):
    if path.exists():
        ref, record = bound_json(path)
        need(record == launch_record(record["unit"]), "existing launch plan differs from closed inputs")
    else:
        record = launch_record(f"horizon-168-joint-continuity-{uuid.uuid4().hex[:12]}.service")
        ref = store(path, record)
    argv = [
        "/usr/bin/systemd-run", "--unit=" + record["unit"], "--service-type=exec",
        "--property=User=root", "--property=StandardOutput=journal",
        "--property=StandardError=journal", "--", *record["argv"],
    ]
    invocation_argv = ["/usr/bin/systemctl", "show", "--property=InvocationID", "--value", record["unit"]]
    print(json.dumps(ref))
    print(shlex.join(argv))
    print(shlex.join(invocation_argv))


def journal(*matches):
    data = subprocess.run(
        ["/usr/bin/journalctl", "--quiet", "--no-pager", "--all", "--output=json", *matches],
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout
    return [json.loads(line) for line in data.splitlines()]


def validated_stdout(rows, record, iid, event):
    need(len(rows) == 3, "expected three original journal stdout records")
    pid = rows[0]["_PID"]
    boot = event["_BOOT_ID"]
    terminal_time = record["joint_terminal_time_us"]
    time = terminal_time
    for label, row in zip(LABELS, rows):
        stamp = int(row["__REALTIME_TIMESTAMP"])
        need(
            row["_SYSTEMD_INVOCATION_ID"] == iid and row["_SYSTEMD_UNIT"] == record["unit"]
            and row["_TRANSPORT"] == "stdout" and row["_BOOT_ID"] == boot and row["_PID"] == pid
            and row["_UID"] == record["uid"] and row["_EXE"] == record["argv"][0]
            and row.get("_CMDLINE", " ".join(record["argv"])) == " ".join(record["argv"])
            and row["MESSAGE"].startswith(label + " ")
            and "\n" not in row["MESSAGE"] and "\r" not in row["MESSAGE"]
            and terminal_time < stamp and time <= stamp <= int(event["__REALTIME_TIMESTAMP"]),
            f"unexpected invocation or timestamp for {label}",
        )
        time = stamp


def capture(launch_path, output, iid):
    _, record = bound_json(launch_path)
    need(record == launch_record(record["unit"]), "launch plan differs from closed inputs")
    unit = record["unit"]
    need(re.fullmatch(r"horizon-168-joint-continuity-[0-9a-f]{12}\.service", unit), "invalid launch service")
    matches = ("_PID=1", "_UID=0", f"UNIT={unit}", f"MESSAGE_ID={SUCCESS}")
    if iid is not None:
        need(re.fullmatch(r"(?!0{32})[0-9a-f]{32}", iid), "invalid comparator invocation ID")
        matches += (f"INVOCATION_ID={iid}",)
    events = journal(*matches)
    need(len(events) == 1, f"expected one PID1 success for {unit}, found {len(events)}")
    [event] = events
    iid = event["INVOCATION_ID"]
    need(
        re.fullmatch(r"(?!0{32})[0-9a-f]{32}", iid) and iid != JOINT_IID and terminal_ok(event, unit, iid),
        "comparison lacks a unique PID1 success",
    )
    rows = journal(f"_SYSTEMD_INVOCATION_ID={iid}", f"_SYSTEMD_UNIT={unit}", "_TRANSPORT=stdout")
    validated_stdout(rows, record, iid, event)
    capture = {k: record[k] for k in ("unit", "uid", "argv", "executable_sha256", "sources", "joint_manifest")}
    capture.update(schema="horizon-epoch168-private-joint-comparison-native-v1",
                   invocation_id=iid, stdout=rows, pid1_event=event)
    print(json.dumps(store(output, capture)))


def checker_deployment():
    checker, data = bound(CHECKER, 0, 16 << 20)
    seal_ref, seal = bound_json(TOOLS / "deployment-seal-receipt.json")
    need(
        checker["sha256"] == CHECKER_SHA and stat.S_IMODE(CHECKER.stat().st_mode) == 0o555
        and seal_ref["sha256"] == CHECKER_SEAL_SHA
        and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
        and seal["destination"] == str(TOOLS)
        and any(m["name"] == CHECKER.name and m["sha256"] == CHECKER_SHA
                and m["bytes"] == len(data) and m["mode"] == "0555" for m in seal["members"]),
        "lineage checker or deployment differs from the qualified build",
    )
    return checker, seal_ref


def completed_selection(path, deployment):
    need(path == SELECTOR_STATE / "RESULT.stdout", "expected the original selector stdout")
    active_ref, active = bound_json(SELECTOR_STATE / "ACTIVE.json")
    need(active_ref["sha256"] == ACTIVE_SHA and active["invocation_id"] == SELECTOR_IID
         and active["unit"] == SELECTOR_UNIT, "selector invocation differs")
    intent_ref, intent = bound_json(SELECTOR_STATE / "START_INTENT.json")
    need(intent_ref == active["intent"] and intent["deployment"] == deployment
         and "--property=StandardOutput=file:" + str(path) in intent["run_argv"],
         "selector output or deployment differs from its launch")
    events = journal("_PID=1", "_UID=0", f"UNIT={SELECTOR_UNIT}",
                     f"INVOCATION_ID={SELECTOR_IID}", f"MESSAGE_ID={SUCCESS}")
    need(len(events) == 1 and terminal_ok(events[0], SELECTOR_UNIT, SELECTOR_IID),
         "waiting for the original selector's successful PID1 terminal event")
    selected, _ = bound_json(path)
    return selected, {"active": active_ref, "intent": intent_ref, "pid1_event": events[0]}


def verify(launch_path, capture_path, selected_path, output_dir):
    _, record = bound_json(launch_path)
    need(record == launch_record(record["unit"]), "launch plan differs from closed inputs")
    cap, capture_record = bound_json(capture_path)
    need(capture_record["unit"] == record["unit"] and capture_record["argv"] == record["argv"],
         "capture does not belong to this launch")
    checker, deployment = checker_deployment()
    selected, terminal = completed_selection(selected_path, deployment)
    plan = store(output_dir / "LINEAGE_PLAN.json", {
        "schema": "horizon-epoch168-private-joint-lineage-plan-v1",
        "joint_terminal": record["joint_terminal"], "joint_manifest": record["joint_manifest"],
        "selected_prefix": selected, "comparison": cap,
        "selector_terminal": terminal, "lineage_checker": checker, "checker_deployment": deployment,
    })
    result = subprocess.run(
        [str(CHECKER), plan["path"], plan["sha256"]], check=True, stdout=subprocess.PIPE,
    )
    print(json.dumps(store(output_dir / "LINEAGE_BINDING.json", json.loads(result.stdout))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(required=True, dest="mode")
    prep = modes.add_parser("prepare", help="check closed metadata, write a launch plan, and print the command")
    prep.add_argument("launch", type=Path)
    cap = modes.add_parser("capture", help="freeze the successful systemd invocation's original journal records")
    cap.add_argument("launch", type=Path)
    cap.add_argument("output", type=Path)
    cap.add_argument("--invocation-id")
    check = modes.add_parser("verify", help="verify the journal and selected retry4 evidence together")
    check.add_argument("launch", type=Path)
    check.add_argument("capture", type=Path)
    check.add_argument("selected_prefix", type=Path)
    check.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    need(os.geteuid() == 0, "root must own this evidence capture")
    if args.mode == "prepare":
        prepare(args.launch)
    if args.mode == "capture":
        capture(args.launch, args.output, args.invocation_id)
    if args.mode == "verify":
        verify(args.launch, args.capture, args.selected_prefix, args.output_dir)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
