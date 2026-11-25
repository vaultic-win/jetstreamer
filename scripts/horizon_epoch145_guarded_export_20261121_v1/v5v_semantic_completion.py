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
CENSUS_RETRY = GENERATION in ("tools-v9-census-recovery", "tools-homefloor-145-v8-census-build-v1")
TIMEOUT_RETRY = CENSUS_RETRY or GENERATION in ("tools-v8-pid1-timeout", "tools-homefloor-145-v7-timeout-build-v2")
STOP_RETRY = TIMEOUT_RETRY or GENERATION in ("tools-v7-168-stop-v2", "tools-homefloor-145-v6-stop-recovery-v2")
WALK_RETRY = STOP_RETRY or GENERATION in ("tools-v6-guard-walk", "tools-homefloor-145-v5z-guard-walk-build-v2")
MODE_RETRY = GENERATION in ("tools-v5z", "tools-homefloor-145-v5y-custody-build-v1") or WALK_RETRY
SCHEMA_RETRY = GENERATION in ("tools-v5y", "tools-homefloor-145-v5x-schema-build-v1") or MODE_RETRY
DONOR_RETRY = GENERATION == "tools-v5x" or SCHEMA_RETRY
RETRY = GENERATION == "tools-v5w" or DONOR_RETRY
V5V_HANDOFF = FAMILY / "v5v-name-handoff"
V5V_PACKAGE = FAMILY / "tools-v5v"
V5V_PROVIDER = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-v5u-guard-recovery-v1"
V5X_HANDOFF = FAMILY / "v5x-name-handoff"
V5Y_HANDOFF = FAMILY / "v5y-name-handoff"
V5Z_HANDOFF = FAMILY / "v5z-name-handoff"
V6_HANDOFF = FAMILY / "v6-guard-walk-name-handoff"
V6 = "a71285e56d674de3bf793692f93dfbb3"
V6_STOP = "cec8b4e1c2903ff7b26960df7e1a3910567a01d60c9dc3292b4733243d5e2b53"
V7_HANDOFF = FAMILY / "v7-168-stop-name-handoff"
V7_START_INTENT = "horizon-epoch145-v6-stop-successor-start-intent-v1"
V7 = "f7043fd6595a4151b659d4b098bede11"
V7_TIMEOUT = "abb572ebbc215821046773de68c3b8ce2afd39113c256f52608ff43296539045"
V7_START = "ed8a68eb322ffeb2788f3017b14fd7c5dfe256f0e95362ed932457bab7d8e487"
V7_RESULT = "4c83262f7bb705f30f1850dcc1274a549b2f08b80618bc23c3c9955fae4f4163"
V7_INTENT = "6340badce38374edd038d7978d29ab60223e6fdea258cef805934866deede7d1"
V7_NATIVE_START = "924732b30001c550af57ae3bbb1f978abc34c1eeb9677276a3f9c1f4a34aaaa5"
V7_EVENT_CLOCKS = (
    ("s=7f76387dd96140468b39dcf01e726fea;i=397938f;b=763ea84ca81f4dddad364b1ea2ba36dd;m=39be973e2c6;t=6611bb6473ffe;x=f5e987fbd627f59c",
     "3968171500230", "1795621510397950"),
    ("s=7f76387dd96140468b39dcf01e726fea;i=3979390;b=763ea84ca81f4dddad364b1ea2ba36dd;m=39be974f8dd;t=6611bb6485614;x=fd4906e4c1bf81be",
     "3968171571421", "1795621510469140"),
    ("s=7f76387dd96140468b39dcf01e726fea;i=397cb3b;b=763ea84ca81f4dddad364b1ea2ba36dd;m=39eae9cbdf3;t=6611e7b701b2b;x=8f9562b41047605",
     "3980069223923", "1795633408121643"),
    ("s=7f76387dd96140468b39dcf01e726fea;i=397cb3c;b=763ea84ca81f4dddad364b1ea2ba36dd;m=39eae9cbe85;t=6611e7b701bbd;x=b3e9ca2dca401fab",
     "3980069224069", "1795633408121789"),
)
V7_SEAL = "589d1da9f51c305be8699a9dc01e443c9ec2367d1f67e7905ba67fdeb0d35c7b"
V7_STATUS_REGISTRATION = {
    "registration": {"path": str(RUNTIME / "epoch166-post168-cadence-20261121-v1/METERED168_STATUS_REGISTERED.json"),
                     "sha256": "02027e3e35364f64913b34162fde295bfb96b3123a9d9794545ce4e0b1a4e8ba"},
    "consumer_seal": {"path": str(RUNTIME / "survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v11-entry146/deployment-seal-receipt.json"),
                      "sha256": "cfcb2a66ab626bb5a0066377f22c65ca424e9e42f4a87f866f6d53be56583a5c"},
    "invocation_id": "048c60372b684a72854aa433c40cbfe8", "pid": 2998320, "start_ticks": 396545999,
}
V8_STATUS_REGISTRATION = {
    "registration": V7_STATUS_REGISTRATION["registration"],
    "consumer_seal": {"path": str(RUNTIME / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v12-entry146/deployment-seal-receipt.json"),
                      "sha256": "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac"},
    "invocation_id": "fbad8843980d458cb3bfc9b5ba5df16b", "pid": 3156031, "start_ticks": 398133937,
}
V8_HANDOFF = FAMILY / "v8-pid1-timeout-name-handoff"
V8_START_INTENT = "horizon-epoch145-v7-timeout-successor-start-intent-v1"
V8 = "e0aa2fa7d85e41578b8489eddd8695b5"
V8_CENSUS_FAILURE = "2ca11551a3f8a9ec55d67366182f3caae3cb089240dff36b3dbb13a131c7f2e5"
V8_RESULT = "6209b4b6a1c8a95803b82dc4d7e385e67ce59519e53b608ce146032eedf915b6"
V8_NATIVE_START = "c740b4d17cc95481c9d6381985de148e87d77aa5c2d18fdcce7fcdb99c5ec10b"
V8_SEAL = "970f9aa956611e499ce1582d37dc845c5e7bfacd639c6002a6c72ccb1a3d718c"
V8_EXIT_CURSOR = "s=7f76387dd96140468b39dcf01e726fea;i=397e3d9;b=763ea84ca81f4dddad364b1ea2ba36dd;m=39fd67e4398;t=6611fa351a0d0;x=cf965a2c6213f3bb"
V9_HANDOFF = FAMILY / "v9-census-name-handoff"
V9_START_INTENT = "horizon-epoch145-v8-census-successor-start-intent-v1"
PACKAGE = (FAMILY / "tools-v9-census-recovery" if CENSUS_RETRY else
           FAMILY / "tools-v8-pid1-timeout" if TIMEOUT_RETRY else FAMILY / "tools-v7-168-stop-v2" if STOP_RETRY else FAMILY / "tools-v6-guard-walk" if WALK_RETRY else FAMILY / "tools-v5z" if MODE_RETRY else
           FAMILY / "tools-v5y" if SCHEMA_RETRY else FAMILY / GENERATION if RETRY else V5V_PACKAGE)
PROVIDER = (V5V_PROVIDER.with_name("tools-homefloor-145-v8-census-recovery-v1") if CENSUS_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v7-timeout-recovery-v1") if TIMEOUT_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v6-stop-recovery-v2") if STOP_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5z-guard-walk-recovery-v1") if WALK_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5y-custody-recovery-v1") if MODE_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5x-schema-recovery-v1") if SCHEMA_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5w-donor-recovery-v1") if DONOR_RETRY else
            V5V_PROVIDER.with_name("tools-homefloor-145-v5v-custody-recovery-v1") if RETRY else V5V_PROVIDER)
V5Z = "4b6a40fe7a4441c28c229ad2b59e2503"
V5Z_WALK_TERMINAL = "80d048defbb9d65e6ab15010705235ebe0f94541ed271f8baa4368ac7c3e7183"
V6_START_INTENT = "horizon-epoch145-v5z-guard-walk-successor-start-intent-v1"
V5Y = "39e0be627a994249915dc8f7a185b438"
V5Y_MODE_TERMINAL = "6e4e62c15adea128211437bc57f9b768ad8f91ac75b720e41e6b267dfc30620d"
V5Z_START_INTENT = "horizon-epoch145-v5y-custody-successor-start-intent-v1"
V5X = "8f1fb9f6620947e8b7e899d2a436d9da"
V5X_SCHEMA_TERMINAL = "b790f288c0b6f2d05a566c2a7e84fe675bcb9e63ae7c07694c53e10b0b5a84dd"
V5Y_START_INTENT = "horizon-epoch145-v5x-schema-successor-start-intent-v1"
V5W = "97bd2045ebe449e3ae77330c7e4ec7b4"
V5W_DONOR_TERMINAL = "8d36ea63912877df362dc33c21d4a834236d4cf36717ee7de9dafadd2153f288"
V5V = "49ef63271f7345bd976c2897296ffbb7"
V5V_CUSTODY = "f2ffaa9026eaeb5fc1616330f8e067742d7a06a96f6f46f12dac8354d7e35a9d"
V5V_RESULT = "feaafe6fd9e0d474c385eadd48e9a57ecc4b29c16b7d20553ae0b62acb51f897"
V5V_INTENT = "8659f84819e07aef5c9ca02fa0f435fc5c67fc021dd8278579dd9693241777ef"
CORRECTED_V5U = "4a4bf1a64a85eeeae092d93643136b74d3fce3602393f34f2f28dea72eedb594"
V7_DONOR_SHA = "667882d8f26e922fa15c3b87dcf738a43a29b3e73ffe9f0b42e50e9120643d9e"
V8_DONOR_SHA = "d4441d0184a8e9c93ed7bc1df6a0a672bc41a86923eec8bc4934178596062ad8"
DONOR_SHA = V8_DONOR_SHA if TIMEOUT_RETRY else V7_DONOR_SHA if STOP_RETRY else "db0b9de9d848a525c0f2daf7810ac8dba85515253e99f8c358eb34e4ba2e5d7c"
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
LIFECYCLE = (STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
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


def pinned_json(ref, path, *, mode=None):
    require(ref["path"] == str(path), f"unexpected binding for {path.name}")
    data, actual = read_file(path, mode=mode)
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


def startup_schema_failure(terminal_ref):
    path = V5X_HANDOFF / "V5X_TERMINAL_FAILURE_STARTUP_SCHEMA.json"
    require(terminal_ref == reference(path, V5X_SCHEMA_TERMINAL), "different V5x startup terminal")
    terminal = pinned_json(terminal_ref, path)
    manager = terminal["manager"]
    require(terminal["schema"] == "horizon-epoch145-v5x-terminal-startup-schema-failure-v1"
            and terminal["boot_id"] == BOOT and terminal["unit"] == manager["Id"] == UNIT
            and terminal["invocation_id"] == manager["InvocationID"] == V5X
            and manager["ActiveState"] == manager["SubState"] == "failed"
            and manager["Result"] == "exit-code" and manager["ExecMainStatus"] == "1"
            and manager["MainPID"] == manager["ControlPID"] == "0"
            and not manager["ControlGroup"] and not manager["Job"]
            and terminal["resource_credit_bytes"] == 0
            and terminal["semantic_completion"] is terminal["archive_publication_authorized"]
            is terminal["r2_mutations"] is False, "different V5x failed native owner")
    prior, prior_exit = donor_lock_failure(terminal["predecessor"])
    intent = pinned_json(terminal["start_intent"], V5X_HANDOFF / "START_INTENT.json")
    result = pinned_json(terminal["start_result"], V5X_HANDOFF / "START_RESULT.json")
    old = STATE / V5X
    failure = pinned_json(terminal["native_failure"], old / "failed.json")
    started = pinned_json(terminal["recovery_started"], old / "recovery-started.json")
    require(terminal["candidate"] == prior["candidate"]
            and intent["schema"] == terminal["actual_start_intent_schema"]
            == "horizon-epoch145-v5w-donor-successor-start-intent-v1"
            and terminal["required_start_intent_schema"] == "horizon-epoch145-v5v-custody-successor-start-intent-v1"
            and result["intent"] == terminal["start_intent"] and result["status"] == 0
            and result["manager"]["InvocationID"] == V5X
            and started["iid"] == failure["iid"] == V5X
            and started["file"] == str(PAID) and started["image"] == terminal["worker"]["sha256"]
            and started["r2_mutations"] is False
            and failure["error"].rstrip().endswith(
                "ValueError: V5x startup cadence selection differs from its sealed launch")
            and {item.name for item in old.iterdir()} == {"failed.json", "recovery-started.json"},
            "different failed V5x startup or paid candidate")
    events = journal(V5X, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    require(events == terminal["native_events"] and [item["MESSAGE_ID"] for item in events] ==
            [STARTING, STARTED, PROCESS_EXIT, FAILURE], "different V5x PID1 terminal sequence")
    validate_start_events(V5X, events[:2], intent["argv"][-5:], intent["not_before_monotonic_usec"], prior_exit)
    scope_event(events[2], V5X, PROCESS_EXIT)
    scope_event(events[3], V5X, FAILURE)
    require(events[2]["EXIT_CODE"] == "exited" and events[2]["EXIT_STATUS"] == "1"
            and events[3]["UNIT_RESULT"] == "exit-code", "different V5x PID1 exit")
    unit_events = journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                          after_cursor=prior_exit["__CURSOR"])
    cutoff = int(events[-1]["__MONOTONIC_TIMESTAMP"])
    require([event for event in unit_events if int(event["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another native owner intervened before V5x failed")
    return terminal, events[-1]


def receipt_mode_failure(terminal_ref):
    path = V5Y_HANDOFF / "V5Y_TERMINAL_FAILURE_RECEIPT_MODE.json"
    require(terminal_ref == reference(path, V5Y_MODE_TERMINAL), "different V5y custody terminal")
    terminal = pinned_json(terminal_ref, path)
    prior, prior_exit = startup_schema_failure(terminal["predecessor"])
    prior_mode = Path(terminal["predecessor"]["path"]).lstat()
    require((prior_mode.st_uid, prior_mode.st_gid, prior_mode.st_nlink, prior_mode.st_mode)
            == (0, 0, 1, stat.S_IFREG | 0o600), "V5x terminal cannot pass native custody")
    intent = pinned_json(terminal["start_intent"], V5Y_HANDOFF / "START_INTENT.json")
    result = pinned_json(terminal["start_result"], V5Y_HANDOFF / "START_RESULT.json")
    quote = pinned_json(terminal["initial_capacity"], V5Y_HANDOFF / "FIT.json")
    manager = terminal["manager"]
    require(terminal["schema"] == "horizon-epoch145-v5y-terminal-receipt-mode-failure-v1"
            and terminal["boot_id"] == BOOT and terminal["unit"] == manager["Id"] == UNIT
            and terminal["invocation_id"] == manager["InvocationID"] == V5Y
            and manager["ActiveState"] == manager["SubState"] == "failed"
            and manager["Result"] == "exit-code" and manager["ExecMainStatus"] == "1"
            and manager["MainPID"] == manager["ControlPID"] == "0"
            and not manager["ControlGroup"] and not manager["Job"]
            and terminal["terminal_output"] == "epoch145: private binding custody"
            and terminal["prior_receipt_original_mode"] == "0400"
            and terminal["prior_receipt_corrected_mode"] == "0600"
            and terminal["pre_read_state_absent"] is True and not (STATE / V5Y).exists()
            and terminal["resource_credit_bytes"] == 0
            and terminal["semantic_completion"] is terminal["archive_publication_authorized"]
            is terminal["r2_mutations"] is False and terminal["candidate"] == prior["candidate"]
            and result["status"] == 0 and result["manager"]["InvocationID"] == V5Y
            and result["intent"] == terminal["start_intent"] and intent["schema"] == V5Y_START_INTENT
            and intent["capacity"] == terminal["initial_capacity"]
            and quote["phase145"]["guard_terminal"] == intent["terminal"] == terminal["predecessor"],
            "different V5y pre-read failure")
    events = journal(V5Y, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    require(events == terminal["native_events"] and [item["MESSAGE_ID"] for item in events] ==
            [STARTING, STARTED, PROCESS_EXIT, FAILURE], "different V5y PID1 terminal sequence")
    validate_start_events(V5Y, events[:2], intent["argv"][-5:], intent["not_before_monotonic_usec"], prior_exit)
    scope_event(events[2], V5Y, PROCESS_EXIT)
    scope_event(events[3], V5Y, FAILURE)
    require(events[2]["EXIT_CODE"] == "exited" and events[2]["EXIT_STATUS"] == "1"
            and events[3]["UNIT_RESULT"] == "exit-code", "different V5y PID1 exit")
    history = journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                      after_cursor=prior_exit["__CURSOR"])
    cutoff = int(events[-1]["__MONOTONIC_TIMESTAMP"])
    require([event for event in history if int(event["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another native owner intervened before V5y failed")
    return terminal, events[-1]


def failed_predecessor(terminal_ref):
    if CENSUS_RETRY:
        terminal, failed = v8_census_failure(terminal_ref)
        return terminal["candidate"], failed
    if TIMEOUT_RETRY:
        terminal, failed = pid1_timeout_failure(terminal_ref)
        return terminal["candidate"], failed
    if STOP_RETRY:
        terminal, failed = guard_stop_failure(terminal_ref)
        return terminal["candidate"], failed
    if WALK_RETRY:
        terminal, failed = guard_walk_failure(terminal_ref)
        return terminal["candidate"], failed
    if MODE_RETRY:
        terminal, failed = receipt_mode_failure(terminal_ref)
        return terminal["candidate"], failed
    if SCHEMA_RETRY:
        terminal, failed = startup_schema_failure(terminal_ref)
        return terminal["candidate"], failed
    if DONOR_RETRY:
        terminal, failed = donor_lock_failure(terminal_ref)
        return terminal["candidate"], failed
    if RETRY:
        terminal, failed = pre_read_failure(terminal_ref)
        return terminal["candidate"], failed
    return v5u_predecessor(terminal_ref)


def guard_walk_failure(terminal_ref):
    path = V5Z_HANDOFF / "V5Z_TERMINAL_FAILURE_GUARD_WALK.json"
    require(terminal_ref == reference(path, V5Z_WALK_TERMINAL), "different V5z guard-walk terminal")
    terminal = pinned_json(terminal_ref, path)
    intent = pinned_json(terminal["start_intent"], V5Z_HANDOFF / "START_INTENT.json")
    result = pinned_json(terminal["start_result"], V5Z_HANDOFF / "START_RESULT.json")
    prior, prior_exit = receipt_mode_failure(intent["terminal"])
    state = STATE / V5Z
    start = pinned_json(terminal["recovery_started"], state / "recovery-started.json")
    failure = pinned_json(terminal["native_failure"], state / "failed.json")
    manager = terminal["manager"]
    require(terminal["schema"] == "horizon-epoch145-v5z-terminal-guard-walk-failure-v1"
            and terminal["boot_id"] == BOOT and terminal["unit"] == manager["Id"] == UNIT
            and terminal["invocation_id"] == manager["InvocationID"] == result["manager"]["InvocationID"] == V5Z
            and manager["ActiveState"] == manager["SubState"] == "failed"
            and manager["MainPID"] == manager["ControlPID"] == manager["NRestarts"] == "0"
            and manager["Result"] == "exit-code" and manager["ExecMainStatus"] == "1"
            and not (manager["ControlGroup"] or manager["Job"])
            and terminal["candidate"] == prior["candidate"] and terminal["resource_credit_bytes"] == 0
            and terminal["semantic_completion"] is terminal["archive_publication_authorized"]
            is terminal["r2_mutations"] is False
            and result["status"] == 0 and result["intent"] == terminal["start_intent"]
            and intent["schema"] == V5Z_START_INTENT and start["image"] == intent["worker"]["sha256"]
            and intent["worker_seal"] == terminal["worker_seal"]
            and intent["provider_seal"] == terminal["provider_seal"]
            and start["iid"] == failure["iid"] == V5Z and start["file"] == str(PAID)
            and failure["error"] == "live guard refused the registered hold: no pair of complete allocation walks for "
                "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1; awaiting a fresh guard sample"
            and {item.name for item in state.iterdir()} == {"recovery-started.json", "failed.json"},
            "different V5z terminal or paid candidate")
    messages = (STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    events = journal(V5Z, *messages)
    require([row["MESSAGE_ID"] for row in events] == [STARTING, STARTED, PROCESS_EXIT, FAILURE]
            and len(events) == len(terminal["native_events"])
            and all(all(saved[key] == value for key, value in current.items())
                    for saved, current in zip(terminal["native_events"], events)),
            "different V5z PID1 terminal sequence")
    validate_start_events(V5Z, events[:2], intent["argv"][-5:], intent["not_before_monotonic_usec"], prior_exit)
    scope_event(events[2], V5Z, PROCESS_EXIT)
    scope_event(events[3], V5Z, FAILURE)
    require(events[2]["EXIT_CODE"] == "exited" and events[2]["EXIT_STATUS"] == "1"
            and events[3]["UNIT_RESULT"] == "exit-code", "different V5z PID1 exit")
    history = journal(None, *messages, after_cursor=prior_exit["__CURSOR"])
    cutoff = int(events[-1]["__MONOTONIC_TIMESTAMP"])
    require([row for row in history if int(row["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another native owner intervened before V5z failed")
    return terminal, events[-1]


def guard_stop_failure(terminal_ref):
    path = V6_HANDOFF / "V6_TERMINAL_FAILURE_168_STOP.json"
    require(terminal_ref == reference(path, V6_STOP), "different V6 guard-stop terminal")
    terminal = pinned_json(terminal_ref, path)
    intent = pinned_json(terminal["start_intent"], V6_HANDOFF / "START_INTENT.json")
    submitted = pinned_json(terminal["start_result"], V6_HANDOFF / "START_RESULT.json")
    prior, prior_exit = guard_walk_failure(intent["terminal"])
    state = STATE / V6
    start = pinned_json(terminal["recovery_started"], state / "recovery-started.json")
    failure = pinned_json(terminal["native_failure"], state / "failed.json")
    stop = terminal["guard_stop_168"]
    stopped = pinned_json(stop["terminal"], Path(stop["terminal"]["path"]))
    require(terminal["schema"] == "horizon-epoch145-v6-terminal-168-guard-stop-v1"
            and terminal["invocation_id"] == start["iid"] == failure["iid"] == V6
            and terminal["unit"] == terminal["manager"]["Id"] == UNIT
            and terminal["manager"]["InvocationID"] == submitted["manager"]["InvocationID"] == V6
            and submitted["status"] == 0 and submitted["intent"] == terminal["start_intent"]
            and intent["schema"] == V6_START_INTENT and start["image"] == intent["worker"]["sha256"]
            and intent["worker_seal"] == terminal["worker_seal"]
            and intent["provider_seal"] == terminal["provider_seal"]
            and terminal["candidate"] == prior["candidate"] and start["file"] == str(PAID)
            and failure["error"].rstrip().endswith("ValueError: replacement admission has no native producer")
            and {p.name for p in state.iterdir()} == {"recovery-started.json", "failed.json"}
            and stopped["producer_invocation_id"] == stop["producer_invocation_id"]
            and stopped["scratch_deleted"] is False and stop["reservation_ending_bytes"] == 0
            and terminal["resource_credit_bytes"] == 0
            and terminal["semantic_completion"] is terminal["archive_publication_authorized"]
            is terminal["r2_mutations"] is False, "different V6 terminal or retained allocation")
    messages = (STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED)
    events = journal(V6, *messages)
    require([row["MESSAGE_ID"] for row in events] == [STARTING, STARTED, PROCESS_EXIT, FAILURE]
            and events[2]["__CURSOR"] == terminal["native_exit"]["__CURSOR"]
            and events[2]["EXIT_CODE"] == "exited" and events[2]["EXIT_STATUS"] == "1"
            and events[3]["UNIT_RESULT"] == "exit-code", "different V6 PID 1 failure")
    validate_start_events(V6, events[:2], intent["argv"][-5:], intent["not_before_monotonic_usec"], prior_exit)
    return terminal, events[-1]


def v7_timeout_terminal():
    return reference(STATE / V7 / "failed.json", V7_TIMEOUT)


def validate_v7_history(events, anchors):
    require([row["MESSAGE_ID"] for row in events] == [STARTING, STARTED, PROCESS_EXIT, FAILURE],
            "different V7 PID1 failure sequence")
    started, _ = validate_start_events(V7, events[:2], anchors["argv_tail"], anchors["intent_floor"],
                                        anchors["predecessor_native"])
    exit_event, failed = events[2:]
    scope_event(exit_event, V7, PROCESS_EXIT)
    scope_event(failed, V7, FAILURE)
    clock_fields = ("__CURSOR", "__MONOTONIC_TIMESTAMP", "__REALTIME_TIMESTAMP")
    require(tuple(tuple(row[key] for key in clock_fields) for row in events) == V7_EVENT_CLOCKS
            and exit_event["COMMAND"] == "ExecStart" and exit_event["EXIT_CODE"] == "exited"
            and exit_event["EXIT_STATUS"] == "1" and failed["UNIT_RESULT"] == "exit-code",
            "different V7 PID1 exit or failure")
    return started, failed


def pid1_timeout_failure(terminal_ref):
    require(terminal_ref == v7_timeout_terminal(), "different V7 PID1 timeout terminal")
    state = STATE / V7
    failure = pinned_json(terminal_ref, state / "failed.json", mode=0o600)
    start_ref = reference(state / "recovery-started.json", V7_START)
    start = pinned_json(start_ref, state / "recovery-started.json", mode=0o600)
    intent_ref = reference(V7_HANDOFF / "START_INTENT.json", V7_INTENT)
    intent = pinned_json(intent_ref, V7_HANDOFF / "START_INTENT.json", mode=0o600)
    result_ref = reference(V7_HANDOFF / "START_RESULT.json", V7_RESULT)
    result = pinned_json(result_ref, V7_HANDOFF / "START_RESULT.json", mode=0o600)
    native_ref = reference(V7_HANDOFF / "NATIVE_START_CHECK.json", V7_NATIVE_START)
    native = pinned_json(native_ref, V7_HANDOFF / "NATIVE_START_CHECK.json", mode=0o600)
    anchors = native["startup_evidence"]
    prior, prior_exit = guard_stop_failure(intent["terminal"])
    fresh = start["fresh_fit"]
    window = fresh["phase145"]["window"]
    require(result["intent"] == anchors["submission_intent"] == intent_ref
            and anchors["submission_result"] == result_ref and anchors["start"] == start_ref
            and result["status"] == 0 and result["manager"]["InvocationID"] == V7
            and native["invocation_id"] == anchors["invocation_id"] == start["iid"] == failure["iid"] == V7
            and result["manager"]["Id"] == intent["unit"] == UNIT
            and intent["schema"] == V7_START_INTENT and intent["terminal"] == anchors["predecessor_terminal"]
            == window["guard_terminal_predecessor"]
            and intent["worker_seal"] == anchors["worker_seal"] == window["continuity_seal"]
            == reference(FAMILY / "tools-v7-168-stop-v2/deployment-seal-receipt.json", V7_SEAL)
            and intent["worker"] == anchors["worker"] and start["image"] == intent["worker"]["sha256"]
            and intent["provider_seal"] == anchors["guard_provider_seal"] == fresh["provider_seal"]
            and intent["provider"] == anchors["guard_provider"]
            and anchors["candidate"] == prior["candidate"] and start["file"] == str(PAID)
            and anchors["argv_tail"] == intent["argv"][-5:]
            and anchors["intent_floor"] == intent["not_before_monotonic_usec"]
            and anchors["predecessor_native"] == prior_exit
            and fresh["status_registration"] == V7_STATUS_REGISTRATION and fresh["fits"] is True
            and native["native_success"] is None and native["publication_authorized"] is False
            and start["r2_mutations"] is intent["r2_mutations"] is False
            and '/session-v4-registered136/status168.py", line 61, in show' in failure["error"]
            and failure["error"].rstrip().endswith(
                "'horizon-qualify-172-full-half-core-20261120-v1.service']' timed out after 10 seconds")
            and {p.name for p in state.iterdir()} == {"recovery-started.json", "failed.json"}
            and not os.path.lexists(V7_HANDOFF / "SEMANTIC_COMPLETION.json"),
            "different V7 startup, timeout, or paid candidate")
    events = journal(V7, *LIFECYCLE)
    started, failed = validate_v7_history(events, anchors)
    history = journal(None, *LIFECYCLE, after_cursor=prior_exit["__CURSOR"])
    cutoff = int(failed["__MONOTONIC_TIMESTAMP"])
    require(started == native["native_start"]
            and [row for row in history if int(row["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another native owner intervened before V7 failed")
    return {"recovery_started": start_ref, "candidate": prior["candidate"],
            "guard_stop_168": prior["guard_stop_168"]}, failed


def v8_census_terminal():
    return reference(STATE / V8 / "failed.json", V8_CENSUS_FAILURE)


def v8_census_failure(terminal_ref):
    require(terminal_ref == v8_census_terminal(), "different V8 census terminal")
    state = STATE / V8
    failure = pinned_json(terminal_ref, state / "failed.json", mode=0o600)
    native_path = V8_HANDOFF / "NATIVE_START_CHECK.json"
    native = pinned_json(reference(native_path, V8_NATIVE_START), native_path, mode=0o600)
    anchors = native["startup_evidence"]
    prior, prior_exit = pid1_timeout_failure(v7_timeout_terminal())
    submission = V8_HANDOFF / "START_RESULT.json"
    result_ref = reference(submission, V8_RESULT)
    result = pinned_json(result_ref, submission, mode=0o600)
    start = pinned_json(anchors["start"], state / "recovery-started.json", mode=0o600)
    worker = FAMILY / "tools-v8-pid1-timeout"
    seal = reference(worker / "deployment-seal-receipt.json", V8_SEAL)
    require(failure["iid"] == result["manager"]["InvocationID"] == start["iid"]
            == anchors["invocation_id"] == native["invocation_id"] == V8
            and result["status"] == 0 and result["intent"] == anchors["submission_intent"]
            and anchors["submission_result"] == result_ref and anchors["worker_seal"] == seal
            and anchors["predecessor_terminal"] == v7_timeout_terminal()
            and anchors["candidate"] == prior["candidate"] and anchors["predecessor_native"] == prior_exit
            and start["file"] == str(PAID) and start["image"] == anchors["worker"]["sha256"]
            and start["fresh_fit"]["status_registration"] == V8_STATUS_REGISTRATION
            and start["fresh_fit"]["phase145"]["window"]["guard_terminal_predecessor"] == v7_timeout_terminal()
            and start["r2_mutations"] is native["publication_authorized"] is False
            and native["native_success"] is None
            and failure["error"].rstrip().endswith("ValueError: unregistered replay process 3187912")
            and {p.name for p in state.iterdir()} == {"recovery-started.json", "failed.json"}
            and not os.path.lexists(V8_HANDOFF / "SEMANTIC_COMPLETION.json"),
            "different V8 startup, census failure, or paid candidate")
    events = journal(V8, *LIFECYCLE)
    require([row["MESSAGE_ID"] for row in events] == [STARTING, STARTED, PROCESS_EXIT, FAILURE],
            "different V8 PID1 lifecycle")
    started, _ = validate_start_events(V8, events[:2], anchors["argv_tail"], anchors["intent_floor"], prior_exit)
    process_exit, failed = events[2:]
    scope_event(process_exit, V8, PROCESS_EXIT)
    scope_event(failed, V8, FAILURE)
    require(native["native_start"] == started and process_exit["__CURSOR"] == V8_EXIT_CURSOR
            and process_exit["EXIT_CODE"] == "exited" and process_exit["EXIT_STATUS"] == "1"
            and failed["UNIT_RESULT"] == "exit-code"
            and int(started["__MONOTONIC_TIMESTAMP"]) < int(process_exit["__MONOTONIC_TIMESTAMP"])
            < int(failed["__MONOTONIC_TIMESTAMP"]),
            "different V8 PID1 failure")
    history = journal(None, *LIFECYCLE, after_cursor=prior_exit["__CURSOR"])
    cutoff = int(failed["__MONOTONIC_TIMESTAMP"])
    require([row for row in history if int(row["__MONOTONIC_TIMESTAMP"]) <= cutoff] == events,
            "another owner intervened before V8 failed")
    return {"recovery_started": anchors["start"], "candidate": prior["candidate"],
            "guard_stop_168": prior["guard_stop_168"]}, failed


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
    if CENSUS_RETRY:
        failure_ref = v8_census_terminal()
        terminal, native_failure = v8_census_failure(failure_ref)
        startup_ref, candidate = terminal["recovery_started"], terminal["candidate"]
        expected["InvocationID"] = V8
        require(fleet["cold168_retry4_root_physical_stop"] == terminal["guard_stop_168"]
                and not journal(None, *LIFECYCLE, after_cursor=native_failure["__CURSOR"]),
                "retained 168 stop or failed V8 owner changed")
    elif TIMEOUT_RETRY:
        failure_ref = v7_timeout_terminal()
        terminal, native_failure = pid1_timeout_failure(failure_ref)
        startup_ref, candidate = terminal["recovery_started"], terminal["candidate"]
        expected["InvocationID"] = V7
        require(fleet["cold168_retry4_root_physical_stop"] == terminal["guard_stop_168"]
                and not journal(None, *LIFECYCLE, after_cursor=native_failure["__CURSOR"]),
                "retained 168 stop or failed V7 owner changed")
    elif STOP_RETRY:
        terminal_ref = reference(V6_HANDOFF / "V6_TERMINAL_FAILURE_168_STOP.json", V6_STOP)
        terminal, native_failure = guard_stop_failure(terminal_ref)
        startup_ref, failure_ref, candidate = terminal["recovery_started"], terminal_ref, terminal["candidate"]
        expected = terminal["manager"]
        properties = tuple(expected)
        require(fleet["cold168_retry4_root_physical_stop"] == terminal["guard_stop_168"]
                and not journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                                after_cursor=native_failure["__CURSOR"]),
                "V6 stop or failed owner changed")
    elif WALK_RETRY:
        terminal_ref = reference(V5Z_HANDOFF / "V5Z_TERMINAL_FAILURE_GUARD_WALK.json", V5Z_WALK_TERMINAL)
        terminal, native_failure = guard_walk_failure(terminal_ref)
        startup_ref, failure_ref, candidate = terminal["recovery_started"], terminal_ref, terminal["candidate"]
        expected = terminal["manager"]
        properties = tuple(expected)
        require(not journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                            after_cursor=native_failure["__CURSOR"]), "another owner followed failed V5z")
    elif MODE_RETRY:
        terminal_ref = reference(V5Y_HANDOFF / "V5Y_TERMINAL_FAILURE_RECEIPT_MODE.json", V5Y_MODE_TERMINAL)
        terminal, native_failure = receipt_mode_failure(terminal_ref)
        startup_ref, failure_ref, candidate = terminal["start_result"], terminal_ref, terminal["candidate"]
        expected = terminal["manager"]
        properties = tuple(expected)
        require(not journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                            after_cursor=native_failure["__CURSOR"]), "another owner followed failed V5y")
    elif SCHEMA_RETRY:
        terminal_ref = reference(V5X_HANDOFF / "V5X_TERMINAL_FAILURE_STARTUP_SCHEMA.json", V5X_SCHEMA_TERMINAL)
        terminal, native_failure = startup_schema_failure(terminal_ref)
        startup_ref, failure_ref, candidate = terminal["recovery_started"], terminal_ref, terminal["candidate"]
        expected = terminal["manager"]
        properties = tuple(expected)
        require(not journal(None, STARTING, STARTED, PROCESS_EXIT, FAILURE, SUCCESS, STOPPING, STOPPED,
                            after_cursor=native_failure["__CURSOR"]), "another owner followed failed V5x")
    elif DONOR_RETRY:
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
    return {"schema": ("horizon-epoch145-v9-predecessor-preflight-v1" if CENSUS_RETRY else
                       "horizon-epoch145-v8-predecessor-preflight-v1" if TIMEOUT_RETRY else
                       "horizon-epoch145-v7-predecessor-preflight-v1" if STOP_RETRY else
                       "horizon-epoch145-v6-predecessor-preflight-v1" if WALK_RETRY else
                       "horizon-epoch145-v5z-predecessor-preflight-v1" if MODE_RETRY else
                       "horizon-epoch145-v5y-predecessor-preflight-v1" if SCHEMA_RETRY else
                       "horizon-epoch145-v5x-predecessor-preflight-v1" if DONOR_RETRY else
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
    schema = V9_START_INTENT if CENSUS_RETRY else V8_START_INTENT if TIMEOUT_RETRY else V7_START_INTENT if STOP_RETRY else V6_START_INTENT if WALK_RETRY else V5Z_START_INTENT if MODE_RETRY else V5Y_START_INTENT if SCHEMA_RETRY else "horizon-epoch145-v5v-custody-successor-start-intent-v1" if retry else (
        "horizon-epoch145-v5u-semantic-successor-start-intent-v1"
    )
    predecessor_invocations = (V5U, V5V, V5W) if retry and DONOR_RETRY else (V5U, V5V) if retry else (V5U,)
    if SCHEMA_RETRY:
        predecessor_invocations += (V5X,)
    if MODE_RETRY:
        predecessor_invocations += (V5Y,)
    if WALK_RETRY:
        predecessor_invocations += (V5Z,)
    if STOP_RETRY:
        predecessor_invocations += (V6,)
    if TIMEOUT_RETRY:
        predecessor_invocations += (V7,)
    if CENSUS_RETRY:
        predecessor_invocations += (V8,)
    require(result["status"] == 0 and manager["Id"] == intent["unit"] == UNIT
            and re.fullmatch(r"[a-f0-9]{32}", iid) and iid not in predecessor_invocations
            and manager["ActiveState"] == "active" and manager["SubState"] == "running"
            and manager["ControlPID"] == manager["NRestarts"] == "0" and not manager["Job"]
            and manager["ControlGroup"] == "/system.slice/" + UNIT and int(manager["MainPID"]) > 1
            and intent["schema"] == schema
            and intent["r2_mutations"] is False, "foreign successful semantic successor submission")
    return iid, int(manager["MainPID"])


def startup(result_ref):
    submission = (V9_HANDOFF if CENSUS_RETRY else V8_HANDOFF if TIMEOUT_RETRY else V7_HANDOFF if STOP_RETRY else V6_HANDOFF if WALK_RETRY else V5Z_HANDOFF if MODE_RETRY else V5Y_HANDOFF if SCHEMA_RETRY
                  else V5X_HANDOFF if DONOR_RETRY else FAMILY / "v5w-name-handoff" if RETRY else V5V_HANDOFF)
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
            and launch_quote["phase145"]["InvocationID"] ==
                (V8 if CENSUS_RETRY else V7 if TIMEOUT_RETRY else V6 if STOP_RETRY else V5Z if WALK_RETRY else V5Y if MODE_RETRY else V5X if SCHEMA_RETRY else V5W if DONOR_RETRY else V5V if RETRY else V5U)
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
    if TIMEOUT_RETRY:
        stage = "v8-drained-census-failure" if CENSUS_RETRY else "v7-drained-pid1-timeout"
        require(launch_quote["phase145"]["stage"] == stage
                and fresh["status_registration"] == V8_STATUS_REGISTRATION,
                "different V8 predecessor price or V12 cadence owner")
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
    schema = ("horizon-epoch145-v8-census-successor-semantic-completion-v1" if CENSUS_RETRY else
              "horizon-epoch145-v7-timeout-successor-semantic-completion-v1" if TIMEOUT_RETRY else
              "horizon-epoch145-v5z-custody-successor-semantic-completion-v1" if MODE_RETRY else
              "horizon-epoch145-v5y-schema-successor-semantic-completion-v1" if SCHEMA_RETRY else
              "horizon-epoch145-v5x-donor-successor-semantic-completion-v1" if DONOR_RETRY else
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
