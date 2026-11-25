"""Authenticate epoch 145 semantic completion from the paid V5u successor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
FAMILY = RUNTIME / "epoch145-semantic-continuity-20261121-v1"
GENERATION = Path(__file__).resolve().parent.name
DONOR_RETRY = GENERATION == "tools-v5x"
RETRY = GENERATION == "tools-v5w" or DONOR_RETRY
V5V_HANDOFF = FAMILY / "v5v-name-handoff"
V5V_PACKAGE = FAMILY / "tools-v5v"
V5V_PROVIDER = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-v5u-guard-recovery-v1"
V5X_HANDOFF = FAMILY / "v5x-name-handoff"
PACKAGE = FAMILY / "tools-v5x" if DONOR_RETRY else FAMILY / "tools-v5w" if RETRY else V5V_PACKAGE
PROVIDER = (V5V_PROVIDER.with_name("tools-homefloor-145-v5w-donor-recovery-v1") if DONOR_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5v-custody-recovery-v1") if RETRY else V5V_PROVIDER)
V5W = "97bd2045ebe449e3ae77330c7e4ec7b4"
V5W_DONOR_TERMINAL = "8d36ea63912877df362dc33c21d4a834236d4cf36717ee7de9dafadd2153f288"
V5V = "49ef63271f7345bd976c2897296ffbb7"
V5V_CUSTODY = "f2ffaa9026eaeb5fc1616330f8e067742d7a06a96f6f46f12dac8354d7e35a9d"
V5V_RESULT = "feaafe6fd9e0d474c385eadd48e9a57ecc4b29c16b7d20553ae0b62acb51f897"
V5V_INTENT = "8659f84819e07aef5c9ca02fa0f435fc5c67fc021dd8278579dd9693241777ef"
CORRECTED_V5U = "4a4bf1a64a85eeeae092d93643136b74d3fce3602393f34f2f28dea72eedb594"
DONOR_SHA = "db0b9de9d848a525c0f2daf7810ac8dba85515253e99f8c358eb34e4ba2e5d7c"
V5U_IMAGE = "18f46b23edd8061eb7ed9ae1566134bc7ea2cbaa6fa7b85cdd1745488366dca4"
V5U_START = "85dede3d71e27414b28369d1686fe4d7e9ee207bcf6ac4a2c083836961149549"
V5U_FAILURE = "635ca9e4a87decf519815c27728b2b49884ff3f4e1149f2542d8f931f3731609"
V5T_TERMINAL = "287ac3b37ff53897d20e0a98519df4bfdec9d186662532dbbd7f84ef07f7e5aa"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state"
OUTPUT = Path("/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1")
PAID = OUTPUT / ".tmp36MvkN"
PROMOTED = OUTPUT / "epoch-145.jet"
VIEW = "/home/sol/.jetstreamer-private/epoch145-prefix-extract-materialized-view-20261121-v1/epoch-145.jet"
SOURCE = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet"
V5U = "8452dba9df42437b9874b35cb44d059f"
ORIGINAL = "de6780b860b3467bae21fbd19176ca14"
BOOT = "763ea84ca81f4dddad364b1ea2ba36dd"
UNIT = "horizon-holding-export145-20261121-v1.service"
BYTES = 105_610_995_833
STARTING = "7d4958e842da4a758f6c1cdc7b36dcc5"
STARTED = "39f53479d3a045ac8e11786248231fbf"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "d9b373ed55a64feb8242e02dbe79a49c"
PROCESS_EXIT = "98e322203f7a4ed290d09fe03c09fe15"
STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"
STOPPED = "9d1aaa27d60140bd96365438aad20286"
EVENT_FIELDS = ("_PID", "_BOOT_ID", "UNIT", "INVOCATION_ID", "MESSAGE_ID", "JOB_TYPE",
                "JOB_RESULT", "COMMAND", "EXIT_CODE", "EXIT_STATUS", "UNIT_RESULT", "MESSAGE")
SHA256 = re.compile(r"[a-f0-9]{64}")


class InvalidCompletion(ValueError):
    pass


class PendingCompletion(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidCompletion(message)


def reference(path, digest):
    return {"path": str(path), "sha256": digest}


def pinned_json(ref, path):
    require(ref["path"] == str(path), f"unexpected binding for {path.name}")
    data, actual = read_file(path)
    require(ref == actual, f"changed SHA-256 binding for {path}")
    return json.loads(data, object_pairs_hook=unique_object)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result


def read_file(path, *, cap=16 << 20, mode=None):
    require(path.is_absolute() and path.resolve(strict=True) == path, f"noncanonical file {path}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022
                and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 < before.st_size <= cap, f"unsafe evidence file {path}")
        data = stream.read(cap + 1)
        require(len(data) == before.st_size
                and file_stamp(before) == file_stamp(os.fstat(stream.fileno())) == file_stamp(path.lstat()),
                f"evidence file changed during inspection {path}")
    return data, reference(path, hashlib.sha256(data).hexdigest())


def read_json(path):
    data, ref = read_file(path)
    return json.loads(data, object_pairs_hook=unique_object), ref


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def frozen_view(info):
    return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size, "mtime_ns": info.st_mtime_ns}


def journal(iid, *messages, after_cursor=None):
    argv = ["/usr/bin/journalctl", "--no-pager", "--quiet", "-ojson",
            "--output-fields=" + ",".join(EVENT_FIELDS), "_PID=1", "_BOOT_ID=" + BOOT,
            "UNIT=" + UNIT]
    if iid is not None:
        argv.append("INVOCATION_ID=" + iid)
    if after_cursor is not None:
        argv.append("--after-cursor=" + after_cursor)
    argv += ["MESSAGE_ID=" + mid for mid in messages]
    lines = subprocess.check_output(argv, text=True, timeout=15).splitlines()
    return [json.loads(line, object_pairs_hook=unique_object) for line in lines]


def scope_event(event, iid, message_id):
    require(all(event[field] == value for field, value in (
        ("_PID", "1"), ("_BOOT_ID", BOOT), ("UNIT", UNIT),
        ("INVOCATION_ID", iid), ("MESSAGE_ID", message_id))),
        "foreign PID1 event")
    require(isinstance(event["__CURSOR"], str) and event["__CURSOR"]
            and int(event["__MONOTONIC_TIMESTAMP"]) > 0 and int(event["__REALTIME_TIMESTAMP"]) > 0,
            "missing PID1 cursor or clock")


def validate_start_events(iid, events, argv_tail, intent_floor, predecessor):
    ids = [event["MESSAGE_ID"] for event in events]
    require(ids[:2] == [STARTING, STARTED], "missing exact PID1 start sequence")
    beginning, started = events[:2]
    scope_event(beginning, iid, STARTING)
    scope_event(started, iid, STARTED)
    command = " ".join(argv_tail)
    require(beginning["JOB_TYPE"] == started["JOB_TYPE"] == "start"
            and started["JOB_RESULT"] == "done"
            and beginning["MESSAGE"] == f"Starting {UNIT} - {command}..."
            and started["MESSAGE"] == f"Started {UNIT} - {command}."
            and int(predecessor["__MONOTONIC_TIMESTAMP"]) < intent_floor
            <= int(beginning["__MONOTONIC_TIMESTAMP"]) < int(started["__MONOTONIC_TIMESTAMP"]),
            "different successor PID1 startup or predecessor clock")
    if len(events) == 2:
        return started, None
    require(ids == [STARTING, STARTED, SUCCESS], "successor has a stopped, failed, or ambiguous PID1 history")
    success = events[-1]
    scope_event(success, iid, SUCCESS)
    require(int(started["__MONOTONIC_TIMESTAMP"]) < int(success["__MONOTONIC_TIMESTAMP"]),
            "successful PID1 terminal event predates the start")
    return started, success


def sealed_member(package, seal_ref, name, mode):
    seal = pinned_json(seal_ref, package / "deployment-seal-receipt.json")
    require(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            and seal["destination"] == str(package)
            and seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            and seal["remote_mutations"] is seal["r2_mutations"] is False,
            f"foreign deployment seal for {package}")
    members = [member for member in seal["members"] if member["name"] == name]
    require(len(members) == 1 and members[0]["mode"] == f"{mode:04o}",
            f"missing sealed member {name}")
    data, ref = read_file(package / name, mode=mode)
    require(ref["sha256"] == members[0]["sha256"], f"sealed bytes changed for {name}")
    return data, ref


def historical_failure():
    previous = FAMILY / "v5r-name-handoff/V5T_FRESH_CENSUS_TERMINAL_105315.json"
    historical = pinned_json(reference(previous, V5T_TERMINAL), previous)
    old_state = STATE / V5U
    start_ref = reference(old_state / "recovery-started.json", V5U_START)
    failure_ref = reference(old_state / "failed.json", V5U_FAILURE)
    start = pinned_json(start_ref, old_state / "recovery-started.json")
    failure = pinned_json(failure_ref, old_state / "failed.json")
    native_exit, native_failure = journal(V5U, PROCESS_EXIT, FAILURE, SUCCESS, STOPPED)
    scope_event(native_exit, V5U, PROCESS_EXIT)
    scope_event(native_failure, V5U, FAILURE)
    phase = start["fresh_fit"]["phase145"]
    candidate = historical["candidate"]
    require(start["iid"] == failure["iid"] == phase["invocation_id"] == V5U
            and start["image"] == V5U_IMAGE and start["file"] == str(PAID)
            and phase["stage"] == "controller" and start["r2_mutations"] is False
            and phase["window"]["guard_terminal_predecessor"] == reference(previous, V5T_TERMINAL)
            and "horizon-epoch159-bounded-vote-trace-20261123-v1.service')' timed out after 10 seconds"
                in failure["error"]
            and native_exit["COMMAND"] == "ExecStart" and native_exit["EXIT_CODE"] == "exited"
            and native_exit["EXIT_STATUS"] == "1" and native_failure["UNIT_RESULT"] == "exit-code"
            and int(native_exit["__MONOTONIC_TIMESTAMP"]) <= int(native_failure["__MONOTONIC_TIMESTAMP"])
            and 0 <= int(native_failure["__REALTIME_TIMESTAMP"]) // 1_000_000 - failure["at"] <= 5
            and {p.name for p in old_state.iterdir()} == {"failed.json", "recovery-started.json"},
            "different drained V5u source receipt or PID1 exit")
    return start_ref, failure_ref, candidate, native_failure


def v5u_predecessor(terminal_ref):
    start_ref, failure_ref, candidate, native_failure = historical_failure()
    require(terminal_ref["path"] == str(FAMILY / "v5v-name-handoff/V5U_TERMINAL.json"),
            "wrong predecessor terminal path")
    terminal = pinned_json(terminal_ref, Path(terminal_ref["path"]))
    require(terminal["schema"] == "horizon-epoch145-v5u-query-timeout-terminal-v1"
            and terminal["startup"] == start_ref and terminal["failure"] == failure_ref
            and terminal["native_failure_cursor"] == native_failure["__CURSOR"]
            and terminal["candidate"] == candidate and terminal["resource_credit_bytes"] == 0
            and terminal["archive_publication_authorized"] is terminal["r2_mutations"] is False
            and all(candidate[k] == v for k, v in (
                ("path", str(PAID)), ("device", 64512), ("inode", 103237059), ("bytes", BYTES))),
            "foreign V5u terminal or paid candidate")
    return candidate, native_failure


def pre_read_failure(terminal_ref):
    expected = reference(V5V_HANDOFF / "START_FAILURE_CUSTODY.json", V5V_CUSTODY)
    require(terminal_ref == expected, "different V5v pre-read terminal receipt")
    terminal = pinned_json(expected, Path(expected["path"]))
    start_ref = reference(V5V_HANDOFF / "START_RESULT.json", V5V_RESULT)
    intent_ref = reference(V5V_HANDOFF / "START_INTENT.json", V5V_INTENT)
    result = pinned_json(start_ref, Path(start_ref["path"]))
    intent = pinned_json(intent_ref, Path(intent_ref["path"]))
    corrected = V5V_HANDOFF / "V5U_TERMINAL.json"
    original_ref = reference(corrected, CORRECTED_V5U)
    _, corrected_ref = read_file(corrected, mode=0o600)
    candidate, old_failure = v5u_predecessor(original_ref)
    require(result["intent"] == intent_ref and successor_manager(result, intent, retry=False)[0] == V5V
            and corrected_ref == intent["terminal"] == original_ref
            and terminal["schema"] == "horizon-epoch145-v5v-pre-read-custody-failure-v1"
            and terminal["invocation_id"] == terminal["manager"]["InvocationID"] == V5V
            and terminal["unit"] == terminal["manager"]["Id"] == UNIT
            and terminal["manager"]["ExecMainStatus"] == "1"
            and terminal["start"] == start_ref and terminal["candidate"] == candidate
            and terminal["terminal_output"] == "epoch145: private binding custody"
            and terminal["correction"] == {
                "receipt": original_ref, "former_mode": "0444", "corrected_mode": "0600",
            }
            and terminal["process_state_directory_created"] is False
            and not os.path.lexists(STATE / V5V)
            and terminal["resource_credit_bytes"] == 0 and terminal["r2_mutations"] is False,
            "different failed V5v admission, corrected custody or private candidate")
    tail = [intent["worker"]["path"], "recover-full-output", intent["fleet"]["path"],
            intent["fleet"]["sha256"], intent["worker"]["sha256"]]
    _, image = sealed_member(V5V_PACKAGE, intent["worker_seal"], "export145", 0o555)
    _, provider = sealed_member(V5V_PROVIDER, intent["provider_seal"], "post-stop-fit", 0o555)
    require(intent["argv"][-5:] == tail and image == intent["worker"] and provider == intent["provider"],
            "different V5v command or sealed deployment")
    events = journal(V5V, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    require([row["MESSAGE_ID"] for row in events] == [STARTING, STARTED, PROCESS_EXIT, FAILURE],
            "different V5v start and fail history")
    started, _ = validate_start_events(V5V, events[:2], tail, intent["not_before_monotonic_usec"], old_failure)
    exited, failed = events[2:]
    scope_event(exited, V5V, PROCESS_EXIT)
    scope_event(failed, V5V, FAILURE)
    require(exited["COMMAND"] == "ExecStart" and exited["EXIT_CODE"] == "exited" and exited["EXIT_STATUS"] == "1"
            and failed["UNIT_RESULT"] == "exit-code"
            and int(started["__MONOTONIC_TIMESTAMP"]) < int(exited["__MONOTONIC_TIMESTAMP"])
            <= int(failed["__MONOTONIC_TIMESTAMP"])
            and terminal["pid1_exit"] == {key: exited[key] for key in
                ("EXIT_CODE", "EXIT_STATUS", "INVOCATION_ID", "__CURSOR", "__REALTIME_TIMESTAMP")},
            "different PID1 exit from the failed V5v invocation")
    history = journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                      after_cursor=old_failure["__CURSOR"])
    cutoff = int(failed["__MONOTONIC_TIMESTAMP"])
    require([row for row in history if int(row["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another native owner intervened before V5v failed")
    return terminal, failed


def donor_lock_failure(terminal_ref):
    path = FAMILY / "v5w-name-handoff/V5W_TERMINAL_FAILURE_DONOR.json"
    require(terminal_ref == reference(path, V5W_DONOR_TERMINAL), "different V5w donor-lock terminal")
    terminal = pinned_json(terminal_ref, path)
    require(terminal["schema"] == "horizon-epoch145-v5w-terminal-donor-lock-failure-v1"
            and terminal["boot_id"] == BOOT and terminal["unit"] == UNIT
            and terminal["invocation_id"] == terminal["manager"]["InvocationID"] == V5W
            and terminal["manager"]["Result"] == "exit-code"
            and terminal["manager"]["MainPID"] == terminal["manager"]["ControlPID"] == "0"
            and terminal["manager"]["ExecMainStatus"] == "1"
            and terminal["semantic_completion"] is False and terminal["r2_mutations"] is False
            and terminal["archive_publication_authorized"] is False and terminal["resource_credit_bytes"] == 0,
            "different terminated V5w manager")
    old = STATE / V5W
    failed = pinned_json(terminal["native_failure"], old / "failed.json")
    started = pinned_json(terminal["recovery_started"], old / "recovery-started.json")
    require(failed["iid"] == started["iid"] == V5W and started["file"] == str(PAID)
            and failed["error"].rstrip().endswith("ValueError: another actor holds the donor; requires its own enrollment")
            and {p.name for p in old.iterdir()} == {"failed.json", "recovery-started.json"},
            "different paid V5w source or failure")
    events = journal(V5W, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    saved = terminal["native_events"]
    require(len(events) == len(saved) == 4 and [event["MESSAGE_ID"] for event in events] ==
            [STARTING, STARTED, PROCESS_EXIT, FAILURE]
            and all(all(record[key] == value for key, value in event.items())
                    for record, event in zip(saved, events, strict=True)),
            "different boot-scoped V5w donor failure sequence")
    exit_event, end = events[-2:]
    scope_event(exit_event, V5W, PROCESS_EXIT)
    scope_event(end, V5W, FAILURE)
    require(exit_event["EXIT_CODE"] == "exited" and exit_event["EXIT_STATUS"] == "1"
            and end["UNIT_RESULT"] == "exit-code", "different V5w native failure")
    return terminal, end


def failed_predecessor(terminal_ref):
    if DONOR_RETRY:
        terminal, failed = donor_lock_failure(terminal_ref)
        return terminal["candidate"], failed
    if RETRY:
        terminal, failed = pre_read_failure(terminal_ref)
        return terminal["candidate"], failed
    return v5u_predecessor(terminal_ref)


def manager_properties(properties):
    output = subprocess.check_output(
        ["/usr/bin/systemctl", "show", "--property=" + ",".join(properties), "--", UNIT],
        text=True, timeout=10)
    return dict(line.split("=", 1) for line in output.splitlines())


def predecessor_preflight(fleet_ref):
    fleet_path = Path(fleet_ref["path"])
    require(fleet_path.parent.parent == RUNTIME
            and re.fullmatch(r"root[0-9]{6}-live166167170-[0-9]{8}-v1", fleet_path.parent.name)
            and fleet_path.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json", "foreign accepted fleet path")
    fleet = pinned_json(fleet_ref, fleet_path)
    row, = [row for row in fleet["epochs"] if row["epoch"] == 145]
    require(fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            and row["inventory_state"] == "missing" and row["no_live_producer_claimed"] is True
            and row["repair_open"] is True, "fleet does not retain the failed private candidate")
    properties = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlPID",
                  "Job", "NRestarts", "ControlGroup", "ExecMainStatus", "Result")

    expected = dict(Id=UNIT, ActiveState="failed", SubState="failed", InvocationID=V5U,
                    MainPID="0", ControlPID="0", Job="", NRestarts="0", ControlGroup="",
                    ExecMainStatus="1", Result="exit-code")
    if DONOR_RETRY:
        terminal_ref = reference(FAMILY / "v5w-name-handoff/V5W_TERMINAL_FAILURE_DONOR.json", V5W_DONOR_TERMINAL)
        terminal, native_failure = donor_lock_failure(terminal_ref)
        expected = terminal["manager"]
        properties = tuple(expected)
        startup_ref, failure_ref, candidate = terminal["recovery_started"], terminal_ref, terminal["candidate"]
    elif RETRY:
        terminal_ref = reference(V5V_HANDOFF / "START_FAILURE_CUSTODY.json", V5V_CUSTODY)
        terminal, native_failure = pre_read_failure(terminal_ref)
        expected = terminal["manager"]
        properties = tuple(expected)
        startup_ref, failure_ref, candidate = terminal["start"], terminal_ref, terminal["candidate"]
    else:
        startup_ref, failure_ref, candidate, native_failure = historical_failure()
    group = Path("/sys/fs/cgroup/system.slice") / UNIT
    require(manager_properties(properties) == expected and not group.exists(), "failed predecessor manager or cgroup changed")
    m = PAID.lstat()
    require(PAID.resolve(strict=True) == PAID and not os.path.lexists(PROMOTED)
            and (m.st_mode, m.st_uid, m.st_gid, m.st_nlink) == (stat.S_IFREG | 0o400, 0, 0, 1)
            and all(k in candidate and candidate[k] == v for k, v in {
                **frozen_view(m), "ctime_ns": m.st_ctime_ns, "allocated_bytes": m.st_blocks * 512,
                "path": str(PAID),
            }.items())
            and file_stamp(m) == file_stamp(PAID.lstat()) and manager_properties(properties) == expected and not group.exists(),
            "paid candidate or failed owner changed during preflight")
    return {"schema": ("horizon-epoch145-v5x-predecessor-preflight-v1" if DONOR_RETRY else
                       "horizon-epoch145-v5w-predecessor-preflight-v1" if RETRY else
                       "horizon-epoch145-v5u-query-timeout-terminal-v1"),
            "fleet_review": fleet_ref, "sampled_at_utc": fleet["sampled_at_utc"],
            "startup": startup_ref, "failure": failure_ref, "candidate": candidate,
            "native_failure_cursor": native_failure["__CURSOR"], "manager": expected,
            "replay_launch_authorized": False, "resource_credit_bytes": 0,
            "archive_publication_authorized": False, "r2_mutations": False}


def successor_manager(result, intent, *, retry=None):
    retry = RETRY if retry is None else retry
    manager = result["manager"]
    iid = manager["InvocationID"]
    schema = "horizon-epoch145-v5v-custody-successor-start-intent-v1" if retry else (
        "horizon-epoch145-v5u-semantic-successor-start-intent-v1"
    )
    predecessor_invocations = (V5U, V5V, V5W) if retry and DONOR_RETRY else (V5U, V5V) if retry else (V5U,)
    require(result["status"] == 0 and manager["Id"] == intent["unit"] == UNIT
            and re.fullmatch(r"[a-f0-9]{32}", iid) and iid not in predecessor_invocations
            and manager["ActiveState"] == "active" and manager["SubState"] == "running"
            and manager["ControlPID"] == manager["NRestarts"] == "0" and not manager["Job"]
            and manager["ControlGroup"] == "/system.slice/" + UNIT and int(manager["MainPID"]) > 1
            and intent["schema"] == schema
            and intent["r2_mutations"] is False, "foreign successful semantic successor submission")
    return iid, int(manager["MainPID"])


def startup(result_ref):
    submission = V5X_HANDOFF if DONOR_RETRY else FAMILY / "v5w-name-handoff" if RETRY else V5V_HANDOFF
    result = pinned_json(result_ref, submission / "START_RESULT.json")
    intent_ref = result["intent"]
    intent = pinned_json(intent_ref, submission / "START_INTENT.json")
    iid, parent = successor_manager(result, intent)
    bounds = intent["fleet"]
    image = intent["worker"]
    argv_tail = [image["path"], "recover-full-output", bounds["path"], bounds["sha256"], image["sha256"]]
    require(intent["argv"][-5:] == argv_tail
            and intent["argv"][0] == "/usr/bin/systemd-run"
            and f"--unit={UNIT.removesuffix('.service')}" in intent["argv"],
            "different semantic successor launch command")
    launch_quote = pinned_json(intent["capacity"], submission / "FIT.json")
    require(launch_quote["fleet"] == bounds and launch_quote["fits"] is True
            and launch_quote["epoch"] == 145 and launch_quote["candidate"] is None
            and launch_quote["phase145"]["InvocationID"] == (V5W if DONOR_RETRY else V5V if RETRY else V5U)
            and launch_quote["phase145"]["guard_terminal"] == intent["terminal"]
            and launch_quote["resource_credit_bytes"] == 0
            and launch_quote["replay_launch_authorized"] is False,
            "different semantic successor funding receipt")

    terminal_ref = intent["terminal"]
    candidate, native = failed_predecessor(terminal_ref)
    start, start_ref = read_json(STATE / iid / "recovery-started.json")
    fresh = start["fresh_fit"]
    phase = fresh["phase145"]
    window = phase["window"]
    image_seal = window["continuity_seal"]
    _, actual_image = sealed_member(PACKAGE, image_seal, "export145", 0o555)
    proof_bytes, actual_proof = sealed_member(PACKAGE, image_seal, "build-proof.json", 0o444)
    proof = json.loads(proof_bytes, object_pairs_hook=unique_object)
    _, provider = sealed_member(PROVIDER, fresh["provider_seal"], "post-stop-fit", 0o555)
    _, donor = sealed_member(PROVIDER, fresh["provider_seal"], "build_159_price.py", 0o444)
    if DONOR_RETRY:
        require(launch_quote["status_registration"] == fresh["status_registration"],
                "different V5x startup cadence owner")
    require(donor["sha256"] == DONOR_SHA and intent["worker_seal"] == image_seal
            and intent["provider_seal"] == fresh["provider_seal"]
            and image == actual_image and window["continuity_build"] == actual_proof
            and image["sha256"] == start["image"] == proof["verifier_sha256"]
            and proof["guard_terminal"] == terminal_ref == window["guard_terminal_predecessor"]
            and start["iid"] == phase["invocation_id"] == iid and phase["stage"] == "controller"
            and window["native_parent"]["pid"] == parent and window["native_parent"]["start_ticks"] > 0
            and start["file"] == str(PAID) and start["r2_mutations"] is False
            and fresh["fits"] is True and fresh["fleet"] == bounds
            and fresh["resource_credit_bytes"] == 0 and provider == intent["provider"],
            "foreign successor worker, startup, or donor retry deployment")
    return {"invocation_id": iid, "start": start_ref, "submission_intent": intent_ref,
            "submission_result": result_ref, "worker": actual_image, "worker_seal": image_seal,
            "worker_build": actual_proof, "guard_provider": provider, "donor": donor,
            "guard_provider_seal": fresh["provider_seal"], "predecessor_terminal": terminal_ref,
            "candidate": candidate, "parent": parent, "intent_floor": intent["not_before_monotonic_usec"],
            "argv_tail": argv_tail, "predecessor_native": native, "native_parent": window["native_parent"]}


def live_successor(anchors):
    parent = anchors["parent"]
    pid = Path("/proc") / str(parent)
    expected = dict(Id=UNIT, InvocationID=anchors["invocation_id"], ActiveState="active",
                    SubState="running", MainPID=str(parent), ControlPID="0", NRestarts="0",
                    Job="", ControlGroup="/system.slice/" + UNIT)
    properties = tuple(expected)
    require(manager_properties(properties) == expected, "native successor is no longer running")
    ticks = int((pid / "stat").read_text().rsplit(") ", 1)[1].split()[19])
    require(ticks == anchors["native_parent"]["start_ticks"]
            and (pid / "exe").readlink() == Path(anchors["worker"]["path"])
            and (pid / "cgroup").read_text().strip() == "0::" + expected["ControlGroup"]
            and (pid / "cmdline").read_bytes() == b"".join(os.fsencode(arg) + b"\0" for arg in anchors["argv_tail"])
            and manager_properties(properties) == expected, "native successor process changed during inspection")


def verify_owner_history(anchors):
    iid = anchors["invocation_id"]
    events = journal(iid, STARTING, STARTED, SUCCESS, FAILURE, PROCESS_EXIT, STOPPING, STOPPED)
    started, success = validate_start_events(iid, events, anchors["argv_tail"], anchors["intent_floor"],
                                             anchors["predecessor_native"])
    unit_events = journal(None, STARTING, STARTED, SUCCESS, FAILURE, PROCESS_EXIT, STOPPING, STOPPED,
                          after_cursor=anchors["predecessor_native"]["__CURSOR"])
    if success is not None:
        end = int(success["__MONOTONIC_TIMESTAMP"])
        unit_events = [event for event in unit_events if int(event["__MONOTONIC_TIMESTAMP"]) <= end]
    require(unit_events == events, "the predecessor unit has a different intervening native owner")
    return started, success


def validate_semantic(verified, extraction, done, anchors, verified_ref, extraction_ref):
    iid = anchors["invocation_id"]
    candidate = anchors["candidate"]
    report = extraction["extraction"]
    projected = dict(report, archive=VIEW)
    require(verified["iid"] == extraction["actor_iid"] == done["iid"] == iid
            and verified["original_export"] == extraction["original_export"] == done["recovered_from"] == ORIGINAL
            and verified["parent"] == anchors["parent"] and type(verified["pid"]) is int and verified["pid"] > 1
            and verified["paid_source"] == str(PAID) and verified["private_projection"] == VIEW
            and all(verified["before"][key] == candidate[key]
                    for key in ("device", "inode", "bytes", "mtime_ns", "ctime_ns"))
            and verified["extraction"] == projected
            and extraction["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
            and extraction["archive_publication_authorized"] is False
            and extraction["recovery_evidence"] == anchors["start"]
            and extraction["verified_frozen"] == verified_ref and done["receipt"] == extraction_ref
            and all(item["r2_mutations"] is False for item in (verified, extraction, done)),
            "broken successor semantic receipt chain")
    expected = {
        "schema": "jetstreamer-private-epoch145-canonical-prefix-extraction-v1",
        "epoch": 145, "archive": str(PROMOTED), "archive_bytes": BYTES,
        "output_slot_start": 62_640_000, "output_slot_count": 432_000,
        "source_archive": SOURCE,
        "source_archive_sha256": "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353",
        "source_manifest_sha256": "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a",
        "worker_sha256": "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
        "source_canonical_checkpoint_slot": 63_072_070,
        "source_canonical_accounts_hash": "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p",
        "retained_verification_tail_slots": 71,
    }
    require(all(report[key] == value for key, value in expected.items())
            and report["source_must_be_retained"] is report["independent_output_reread_passed"] is True
            and all(report[flag] is False for flag in ("current_plugin_verification_passed",
                    "canonical_sidecar_authorized", "publication_authorized", "retirement_authorized", "r2_mutations"))
            and all(isinstance(report[key], str) and SHA256.fullmatch(report[key]) for key in
                    ("archive_sha256", "output_semantic_sha256", "expected_output_provenance_sha256")),
            "foreign epoch 145 range or semantic provenance")
    return report


def completion(anchors, started, success):
    iid = anchors["invocation_id"]
    state = STATE / iid
    require(not (state / "failed.json").exists(), "successor wrote a failed receipt")
    if success is None:
        raise PendingCompletion("awaiting generation-matched PID1 success")
    done, done_ref = read_json(state / "complete.json")
    extraction_ref = done["receipt"]
    extraction = pinned_json(extraction_ref, state / "extraction-complete.json")
    verified_ref = extraction["verified_frozen"]
    verified = pinned_json(verified_ref, state / "verified-frozen.json")
    report = validate_semantic(verified, extraction, done, anchors, verified_ref, extraction_ref)
    born = int(started["__REALTIME_TIMESTAMP"]) // 1_000_000
    finished = int(success["__REALTIME_TIMESTAMP"]) // 1_000_000
    require(born <= extraction["at_unix_seconds"] <= done["at"] <= finished,
            "semantic receipt timestamps fall outside the PID1 run")
    require(PROMOTED.resolve(strict=True) == PROMOTED and not os.path.lexists(PAID),
            "paid archive did not promote to the exact path")
    info = PROMOTED.lstat()
    identity = frozen_view(info)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o400
            and all(value == anchors["candidate"][key] for key, value in identity.items()),
            "foreign promoted inode")
    require(not (state / "failed.json").exists() and file_stamp(info) == file_stamp(PROMOTED.lstat()),
            "promoted archive or terminal state changed")
    schema = ("horizon-epoch145-v5x-donor-successor-semantic-completion-v1" if DONOR_RETRY else
              "horizon-epoch145-v5v-custody-successor-semantic-completion-v1" if RETRY else
              "horizon-epoch145-v5u-successor-semantic-completion-v1")
    return {"schema": schema, "invocation_id": iid, "start": anchors["start"], "verified": verified_ref,
            "extraction": extraction_ref, "completion": done_ref, "pid1_success": success["__CURSOR"],
            "native_start": started, "native_success": success, "archive": str(PROMOTED),
            "archive_bytes": BYTES, "archive_sha256": report["archive_sha256"],
            "provenance_sha256": report["expected_output_provenance_sha256"], "identity": identity,
            "startup_evidence": anchors, "publication_authorized": False, "r2_mutations": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-start", action="store_true", help="report checked startup while the generation runs")
    parser.add_argument("--inspect-predecessor", action="store_true",
                        help="validate the drained predecessor using the supplied accepted fleet")
    parser.add_argument("receipt", type=Path, help="absolute path to the native start result or accepted fleet")
    parser.add_argument("receipt_sha256", help="digest of the supplied receipt")
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                "use a privileged isolated interpreter with bytecode writes disabled")
        require(SHA256.fullmatch(args.receipt_sha256), "invalid receipt SHA-256")
        require(not (args.inspect_predecessor and args.check_start), "ambiguous inspection mode")
        ref = reference(args.receipt, args.receipt_sha256)
        if args.inspect_predecessor:
            print(json.dumps(predecessor_preflight(ref), indent=2, sort_keys=True))
            return 0
        anchors = startup(ref)
        iid = anchors["invocation_id"]
        started, success = verify_owner_history(anchors)
        if args.check_start:
            require(success is None, "native successor already completed")
            live_successor(anchors)
            result = {"invocation_id": iid, "native_start": started, "native_success": success,
                      "startup_evidence": anchors, "publication_authorized": False}
        else:
            result = completion(anchors, started, success)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except PendingCompletion as error:
        print(f"pending: {error}", file=sys.stderr)
        return os.EX_TEMPFAIL
    except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
