"""Submit the reviewed retirement immediately after one specific native check succeeds."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import time


PRIVATE = Path("/home/sol/.jetstreamer-private/epoch166-retry10-consumer-review-20261123")
OPERATOR = PRIVATE / "run-reviewed-transition.py"
OPERATOR_SHA = "3f27fe2257f91cb7fdbc891111f4817652c73bbd47c3b297a249a7ee71679593"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_program(path, digest):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, f"changed program {path}")


def service(unit):
    fields = "InvocationID,SubState,MainPID,Result,NRestarts,ExecMainStatus"
    rows = subprocess.check_output(["systemctl", "show", unit, "-p", fields], text=True)
    return dict(line.split("=", 1) for line in rows.splitlines())


def wait_for_check(unit, invocation):
    def current():
        row = service(unit)
        require(row["InvocationID"] == invocation and row["NRestarts"] == "0",
                "native check changed generation")
        return row

    row = current()
    if int(row["MainPID"]):
        pid = int(row["MainPID"])
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            fd = None
        if fd is not None:
            try:
                require(current()["MainPID"] in (str(pid), "0"), "native PID changed")
                poll = select.poll()
                poll.register(fd, select.POLLIN)
                require(poll.poll(30 * 60 * 1000), "native check is still running")
            finally:
                os.close(fd)
    # PID 1 may still be dispatching the exit notification after pidfd becomes readable.
    for _ in range(40):
        row = current()
        if row["SubState"] != "start":
            break
        time.sleep(0.1)
    require((row["SubState"], row["MainPID"], row["Result"], row["ExecMainStatus"])
            == ("exited", "0", "success", "0"), "native check did not exit successfully")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("submission", type=Path)
    parser.add_argument("submission_sha")
    parser.add_argument("invocation")
    parser.add_argument("preparer_sha")
    args = parser.parse_args()
    require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
            "run as root with python3 -IB")
    verify_program(OPERATOR, OPERATOR_SHA)
    ops = runpy.run_path(str(OPERATOR))
    read, ref = ops["read"], ops["ref"]
    require(args.submission.parent.parent == ops["FOLDER"] and args.submission.name == "SUBMIT.json",
            "unexpected submission path")
    submitted = read({"path": str(args.submission), "sha256": args.submission_sha})
    handoff = read(submitted["handoff"])
    plan = read(handoff["plan"])
    origin = submitted["origin"]
    read(origin)
    require(plan["prior_check"] is None and submitted["cmd"] == handoff["check_service_argv"],
            "submission is not the reviewed check")
    unit = submitted["unit"]
    expected = "horizon-closed166-retry10-check-" + Path(submitted["handoff"]["path"]).parent.name.removeprefix("prepare-check-")
    require(unit == expected + ".service", "unexpected native check unit")
    verify_program(ops["BINDER"], args.preparer_sha)

    # Serialize followers on this exact immutable submission without modifying it.
    with args.submission.open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wait_for_check(unit, args.invocation)
        pattern = "retire166-retry10-check-" + handoff["plan"]["sha256"] + "-*.json"
        receipts = list((ops["STATE"] / "receipts").glob(pattern))
        require(len(receipts) == 1, "expected one receipt for the submitted plan")
        receipt_ref = ref(receipts[0])
        receipt = read(receipt_ref)
        require(receipt["checked"] and not receipt["data_removed"]
                and receipt["consumer_closure"] == handoff["consumer_closure"],
                "check receipt does not cover this closure")
        require(0 <= time.time() - receipt["recorded_unix_seconds"] < 900,
                "native check receipt expired")
        for previous in ops["FOLDER"].glob("execute-*/SUBMIT.json"):
            used = read(read(ref(previous))["handoff"])
            require(read(used["plan"])["prior_check"] != receipt_ref,
                    f"execution already submitted for this check: {previous}")

        verify_program(ops["BINDER"], args.preparer_sha)
        verify_program(OPERATOR, OPERATOR_SHA)
        python = [sys.executable, "-IB"]
        command = python + [ops["BINDER"], "prepare-execute", "--fleet", ops["fleet"](),
                            "--origin-proof", origin["path"], "--origin-sha", origin["sha256"],
                            "--prior-check", receipt_ref["path"], "--prior-sha", receipt_ref["sha256"]]
        prepared = json.loads(subprocess.check_output(command, text=True))
        execute = read(prepared)
        require(read(execute["plan"])["prior_check"] == receipt_ref,
                "prepared execute plan references a different check")
        for mode in ("plan", "start"):
            subprocess.run(python + [OPERATOR, mode, "execute", origin["path"], origin["sha256"],
                                     prepared["path"], prepared["sha256"]], check=True)


if __name__ == "__main__":
    main()
