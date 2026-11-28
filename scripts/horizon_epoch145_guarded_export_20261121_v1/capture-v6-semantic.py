"""Persist the checked epoch 145 V6 semantic receipt after PID 1 success."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
sys.path.insert(0, str(RUNTIME / "prefix140-status-cadence-20261122-v1/cadence-tools"))
from evidence import bound, checked, durable, need

FAMILY = RUNTIME / "epoch145-semantic-continuity-20261121-v1"
HANDOFF = FAMILY / "v6-guard-walk-name-handoff"
PACKAGE = FAMILY / "tools-v6-guard-walk"
START_SHA = "6eb0a91c59e96a6e0be337c130610f8264e8195c6a2da7a84b456551c2b2b996"
SEAL_SHA = "cdd5008739fb790d52fd7d659efec63a5932bd4e375f40cb3e1679611c6d2f68"
INVOCATION = "a71285e56d674de3bf793692f93dfbb3"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"


def main():
    need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
         "use a privileged isolated interpreter with bytecode writes disabled")
    need(sys.argv[1:] in ([], ["--check-start"]), "unexpected capture arguments")
    checker = PACKAGE / "v5v_semantic_completion.py"
    seal_ref = bound(PACKAGE / "deployment-seal-receipt.json")
    start_ref = bound(HANDOFF / "START_RESULT.json")
    need(seal_ref["sha256"] == SEAL_SHA and start_ref["sha256"] == START_SHA,
         "different V6 deployment or native start")
    seal = checked(seal_ref)
    entry, = (row for row in seal["members"] if row["name"] == checker.name)
    need(seal["destination"] == str(PACKAGE) and bound(checker)["sha256"] == entry["sha256"]
         and entry["mode"] == "0444" and stat.S_IMODE(checker.stat().st_mode) == 0o444,
         "different V6 completion checker")
    argv = ["/usr/bin/python3", "-IB", str(checker), *sys.argv[1:],
            start_ref["path"], start_ref["sha256"]]
    if sys.argv[1:]:
        report = json.loads(subprocess.check_output(argv, timeout=45))
        need(report["invocation_id"] == INVOCATION and report["native_success"] is None,
             "different live V6 owner")
        print(json.dumps({"invocation_id": INVOCATION, "start": start_ref, "seal": seal_ref}))
        return

    deadline = time.monotonic() + 60
    while True:
        result = subprocess.run(argv, capture_output=True, timeout=45)
        if result.returncode != os.EX_TEMPFAIL or time.monotonic() >= deadline:
            break
        time.sleep(2)
    need(result.returncode == 0, result.stderr.decode().strip() or "V6 completion checker failed")
    report = json.loads(result.stdout)
    native = report["native_success"]
    need(report["invocation_id"] == INVOCATION and native["INVOCATION_ID"] == INVOCATION
         and native["_PID"] == "1" and native["MESSAGE_ID"] == SUCCESS
         and native["__CURSOR"] == report["pid1_success"]
         and report["publication_authorized"] is report["r2_mutations"] is False,
         "different V6 semantic terminal")
    output = HANDOFF / "SEMANTIC_COMPLETION.json"
    durable(output, report)
    need(checked(bound(output)) == report, "captured V6 completion changed")
    print(json.dumps({"semantic_completion": bound(output), "invocation_id": INVOCATION,
                      "archive_sha256": report["archive_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
