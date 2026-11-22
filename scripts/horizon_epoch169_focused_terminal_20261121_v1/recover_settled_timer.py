"""Register the original focused 169 timer stop after PID 1 discarded its transient unit."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-terminal-20261121-v1")
TERMINAL_SHA = "218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"
PKG = ROOT / "closure-tools"
SEAL_SHA = "63b5ba5c870820feae7bcbc15b61f2872a0c13b6b3b22295775873cbfab676b3"
START = "39f53479d3a045ac8e11786248231fbf"
STOP = "9d1aaa27d60140bd96365438aad20286"
FIELDS = "_BOOT_ID,_PID,UNIT,INVOCATION_ID,MESSAGE_ID,JOB_TYPE,JOB_RESULT"


def require(test, reason):
    if not test:
        raise ValueError(reason)


def closure():
    seal = (PKG / "deployment-seal-receipt.json").read_bytes()
    require(hashlib.sha256(seal).hexdigest() == SEAL_SHA, "different original closure package")
    members = {entry["name"]: entry for entry in json.loads(seal)["members"]}
    for name in ("closure169.py", "original169.py"):
        require(hashlib.sha256((PKG / name).read_bytes()).hexdigest() == members[name]["sha256"],
                "different original closure member")
    return runpy.run_path(str(PKG / "closure169.py"))


def job(rows, boot, unit, iid, kind):
    message = {"stop": STOP, "start": START}[kind]
    require(len(rows) == 1, "missing or ambiguous original systemd job")
    event = rows[0]
    expected = {"_PID": "1", "_BOOT_ID": boot, "UNIT": unit, "INVOCATION_ID": iid,
                "MESSAGE_ID": message, "JOB_TYPE": kind, "JOB_RESULT": "done"}
    require(all(event.get(k) == v for k, v in expected.items()), "job belongs to another actor or outcome")
    require(bool(event["__CURSOR"]) and int(event["__MONOTONIC_TIMESTAMP"]) > 0, "missing journal position")
    return {k: event[k] for k in (*expected, "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP")}


def manager_job(boot, unit, iid, kind):
    message = {"stop": STOP, "start": START}[kind]
    raw = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-ojson", "--output-fields=" + FIELDS,
        "_PID=1", "_BOOT_ID=" + boot, "UNIT=" + unit, "INVOCATION_ID=" + iid,
        "JOB_TYPE=" + kind, "MESSAGE_ID=" + message], timeout=20)
    return job([json.loads(line) for line in raw.splitlines()], boot, unit, iid, kind)


def event_order(start, stop, guard_done, producer_end, sample_seconds):
    require(int(start["__MONOTONIC_TIMESTAMP"]) < int(stop["__MONOTONIC_TIMESTAMP"])
            <= int(producer_end["__MONOTONIC_TIMESTAMP"]) <= int(guard_done["__MONOTONIC_TIMESTAMP"]),
            "timer stop outside original producer and guard shutdown")
    require(sample_seconds * 1_000_000 <= int(stop["__REALTIME_TIMESTAMP"])
            <= int(guard_done["__REALTIME_TIMESTAMP"]), "different guard trip")


def recover(c, commit):
    shared = c["shared"]
    guard = c["guard"]
    binding = guard.committed()
    term, tref = shared["document"](c["TERM"], 0o400, TERMINAL_SHA)
    require(binding["terminal"] == tref and binding["disposition"] == c["INTERRUPTED"]
            and term["guard_stop"]["reason"] == "root-physical-budget"
            and term["private_segment"] is None and term["resource_credit_bytes"] == term["reservation_ending_bytes"] == 0,
            "different diagnostic terminal")
    first, _ = shared["document"](Path(binding["first_guard"]["path"]), 0o400, binding["first_guard"]["sha256"])
    before = first["timer"]
    guard.expected_timer(before)
    ref = term["guard_stop"]["sample"]
    sample, _ = shared["document"](Path(ref["path"]), 0o600, ref["sha256"])
    boot = c["o"]["boot"]().replace("-", "")
    start = manager_job(boot, guard.guard_timer, guard.guard_timer_id, "start")
    stop = manager_job(boot, guard.guard_timer, guard.guard_timer_id, "stop")
    guard_done = manager_job(boot, guard.guard_service, sample["guard_invocation_id"], "start")
    event_order(start, stop, guard_done, term["manager_terminal"]["events"][-1], sample["recorded_unix_seconds"])

    def observe():
        actors = [shared["drained"](name) for name in (guard.guard_timer, guard.guard_service, guard.producer_unit)]
        require(all(row["LoadState"] == "not-found" and not row.get("InvocationID") for row in actors),
                "replacement or registered unit present")
        return actors

    after = observe()
    intent = {"binding": binding, "before": before, "before_source": binding["first_guard"],
              "recovery": "previously stopped original timer", "timer_start": start, "timer_stop": stop,
              "final_guard_job": guard_done, "stop_sample": ref}
    proof = {"binding": binding, "after": after[:2]}
    if not commit:
        return {"intent": intent, **proof, "producer_after": after[2]}
    with (ROOT / "terminal-guard-retirement.lock").open("r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(guard.committed() == binding and observe() == after, "owner changed at recovery boundary")
        ir = shared["once"](guard.intent_path, intent)
        require(guard.committed() == binding and observe() == after, "owner changed after intent")
        shared["once"](guard.completion_path, dict(proof, intent=ir))
        return guard.inspect()


if __name__ == "__main__":
    require(os.geteuid() == 0 and sys.flags.isolated and __debug__ and sys.argv[1:] in (["check"], ["record"]),
            "run isolated as root with check or record")
    print(json.dumps(recover(closure(), sys.argv[1] == "record"), sort_keys=True))
