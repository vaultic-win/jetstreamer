"""Authenticate the independent frozen epoch 145 reread for bounded entry 146."""

import json
import os
from pathlib import Path
import re
import runpy
import subprocess

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
READERS = RUNTIME / "epoch145-parallel-full-verification-20261126-v1"
ARCHIVE = Path("/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN")
LOCK = ARCHIVE.parent.parent / "r2-holding-state-dev-samjohnson-v1/transition.lock"
STAGE = "independent-semantic-complete-v10-drained"
V10 = "104f023c5cd24a55b6585ef525b80067"
BOOT = "763ea84ca81f4dddad364b1ea2ba36dd"
UNIT = "horizon-holding-export145-20261121-v1.service"
STARTED = "39f53479d3a045ac8e11786248231fbf"
STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"
STOPPED = "9d1aaa27d60140bd96365438aad20286"
SELECT_SCHEMA = "horizon-epoch146-independent-145-selection-v1"
TERMINAL_SCHEMA = "horizon-epoch145-independent-terminal-acceptance-v1"
SELECT = "independent145-selection.json"

# Both bindings identify reviewed collectors that reopen the current exact PID1
# terminal, invocation journal, verifier image and frozen archive.
CANDIDATES = {
    "four": {
        "root": READERS,
        "unit": "horizon-145-parallel-full-verification-20261126-v1.service",
        "invocation": "cb3313b857d94b9f82e06d5c033c0ac5",
        "collector_sha256": "22224cb431601419e5bef87f7af0a67d29c31d528fb9bc7a9d7806dc086acc6f",
    },
    "scaled": {
        "root": READERS / "scaled-candidate-v1",
        "unit": "horizon-145-scaled-independent-verification-20261126-v1.service",
        "invocation": "a89c1de125694cb3bdcef19a8c82848a",
        "collector_sha256": "66c3c08371b3e41818678c7c0105fb037c49b75d2c1095d6ebee2a20e8d0e5f0",
    },
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def terminal_path(candidate):
    return candidate["root"] / "INDEPENDENT_TERMINAL_ACCEPTED.json"


def lookup(selection):
    require(isinstance(selection, dict) and
            set(selection) == {"schema", "candidate", "terminal"} and selection["schema"] == SELECT_SCHEMA
            and isinstance(selection["candidate"], str) and selection["candidate"] in CANDIDATES,
            "foreign independent epoch 145 selection")
    candidate = CANDIDATES[selection["candidate"]]
    binding = selection["terminal"]
    require(isinstance(binding, dict) and set(binding) == {"path", "sha256"}
            and binding["path"] == str(terminal_path(candidate))
            and isinstance(binding["sha256"], str) and re.fullmatch("[0-9a-f]{64}", binding["sha256"]),
            "foreign independent epoch 145 terminal binding")
    return candidate, binding


def checked_terminal(status, fit, candidate, binding):
    receipt, actual = status.read(terminal_path(candidate), binding["sha256"])
    require(actual == binding and terminal_path(candidate).stat().st_mode & 0o777 == 0o400,
            "changed independent epoch 145 terminal receipt")
    collector = candidate["root"] / "capture-independent-terminal.py"
    require(collector.lstat().st_mode & 0o777 == 0o400, "changed independent epoch 145 collector")
    fit.binary(collector, candidate["collector_sha256"])
    current = runpy.run_path(str(collector))["capture"]()
    fit.binary(collector, candidate["collector_sha256"])
    native = receipt["native"]
    report = receipt["report"]
    require(receipt == current and receipt["schema"] == TERMINAL_SCHEMA and receipt["epoch"] == 145
            and receipt["publication_authorized"] is False and receipt["r2_mutations"] is False
            and native["Id"] == candidate["unit"] and native["InvocationID"] == candidate["invocation"]
            and report["invocation_id"] == candidate["invocation"] and report["output_promoted"] is False
            and report["frozen_output"] == str(ARCHIVE) and report["source_tail_verified"] is True
            and report["verified_canonical_slots"] == 432000 and report["verified_buckets"] == 3375
            and isinstance(receipt["journal_time_us"], str) and receipt["journal_time_us"].isdigit(),
            "foreign or incomplete independent epoch 145 terminal")
    return receipt, status.ref(collector, candidate["collector_sha256"])


def drained(status, fit):
    manager = status.show(fit.A145)
    require(fit.A145 == UNIT and manager["Id"] == UNIT
            and (manager["ActiveState"], manager["SubState"]) in (("inactive", "dead"), ("failed", "failed"))
            and manager["MainPID"] == manager["ControlPID"] == "0" and manager["NRestarts"] == "0"
            and manager["InvocationID"] in ("", V10) and manager["Job"] == ""
            and not fit.members(UNIT), "epoch 145 V10 verifier has not drained")
    lock = LOCK.stat()
    require((lock.st_dev, lock.st_ino, lock.st_uid, lock.st_gid, lock.st_nlink, lock.st_mode & 0o777)
            == (64512, 95818311, 0, 0, 1, 0o600) and LOCK.resolve(strict=True) == LOCK,
            "foreign holding transition lock")
    token = f"{os.major(lock.st_dev):02x}:{os.minor(lock.st_dev):02x}:{lock.st_ino}"
    require(not any(token in row.split() for row in Path("/proc/locks").read_text().splitlines()),
            "holding transition remains occupied")
    return manager


def other_readers_drained(status, fit, candidate):
    units = {item["unit"] for item in CANDIDATES.values()} - {candidate["unit"]}
    units.add("horizon-145-scaled-window-benchmark-20261126-v1.service")
    for unit in sorted(units):
        native = status.show(unit)
        require(native["Id"] == unit and native["MainPID"] == native["ControlPID"] == "0"
                and not native["Job"] and not fit.members(unit) and (native["ActiveState"], native["SubState"])
                in (("inactive", "dead"), ("failed", "failed"), ("active", "exited")),
                f"unaccounted epoch 145 verifier still live: {unit}")


def native_handback(verified_at):
    raw = subprocess.check_output(
        ["/usr/bin/journalctl", "--no-pager", "--quiet", "-ojson", "--lines=10",
         "_PID=1", "_BOOT_ID=" + BOOT, "UNIT=" + UNIT,
         "MESSAGE_ID=" + STARTED, "MESSAGE_ID=" + STOPPING, "MESSAGE_ID=" + STOPPED],
        text=True, timeout=10)
    events = [json.loads(line) for line in raw.splitlines()]
    return stop_contract(events[-3:], verified_at)


def stop_contract(events, verified_at):
    require([row["MESSAGE_ID"] for row in events] == [STARTED, STOPPING, STOPPED]
            and all(row["_PID"] == "1" and row["_BOOT_ID"] == BOOT and row["UNIT"] == UNIT
                    and row["INVOCATION_ID"] == V10 and row["__CURSOR"] for row in events),
            "foreign V10 stop or intervening native owner")
    started, stopping, stopped = events
    require(started["JOB_TYPE"] == "start" and started["JOB_RESULT"] == "done"
            and stopping["JOB_TYPE"] == stopped["JOB_TYPE"] == "stop" and stopped["JOB_RESULT"] == "done"
            and int(started["__REALTIME_TIMESTAMP"]) < int(verified_at)
            <= int(stopping["__REALTIME_TIMESTAMP"]) <= int(stopped["__REALTIME_TIMESTAMP"])
            and int(started["__MONOTONIC_TIMESTAMP"]) < int(stopping["__MONOTONIC_TIMESTAMP"])
            <= int(stopped["__MONOTONIC_TIMESTAMP"]),
            "V10 did not drain after the independent verification")
    return {"started": started["__CURSOR"], "stopping": stopping["__CURSOR"], "stopped": stopped["__CURSOR"]}


def phase(status, fit, package, selection_sha):
    selection_path = package / SELECT
    selection, selection_ref = status.read(selection_path, selection_sha)
    require(selection_path.lstat().st_mode & 0o777 == 0o444, "unsealed independent epoch 145 selection")
    candidate, binding = lookup(selection)
    manager = drained(status, fit)
    other_readers_drained(status, fit, candidate)
    receipt, collector = checked_terminal(status, fit, candidate, binding)
    handback = native_handback(receipt["journal_time_us"])
    require(drained(status, fit) == manager, "epoch 145 custody changed during verification")
    other_readers_drained(status, fit, candidate)
    return {
        "Id": UNIT, "MainPID": "0", "stage": STAGE,
        "completed_invocation_id": candidate["invocation"], "verifier_unit": candidate["unit"],
        "semantic_receipt": binding, "collector": collector, "selection": selection_ref,
        "previous_verifier_invocation_id": V10, "native_handback": handback,
        "resource_credit_bytes": 0,
    }
