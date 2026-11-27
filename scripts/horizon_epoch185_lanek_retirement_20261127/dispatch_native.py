#!/usr/bin/python3
"""Run one funded check or removal and bind the native result to its exact PID1 invocation."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import time

UNIT = "horizon-exact-185-lanek-retirement.service"
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1")
STATE = Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1")
PROGRAM = ROOT / "retirement-tools-v3/retire-lanek185"
PROGRAM_SHA = "41b2284f2adafa993d814c3715b23a8926a9f8efe8ef6ec96bee041ea7383725"
PLAN = ROOT / "RETIREMENT_PLAN_AFTER_CUSTODY.json"
EVIDENCE = runpy.run_path(str(ROOT / "retirement-tools-v3/prepare-after-park.py"))
read = EVIDENCE["read"]
need = EVIDENCE["need"]
persist = EVIDENCE["persist"]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native():
    properties = "Id,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ExecMainPID,Result"
    result = subprocess.run(["/usr/bin/systemctl", "show", UNIT, "-p", properties], capture_output=True, text=True)
    need(result.returncode in (0, 4), "unavailable native manager")
    row = dict(line.split("=", 1) for line in result.stdout.splitlines())
    need(row["Id"] == UNIT and (result.returncode == 0 or row["LoadState"] == "not-found"), "wrong unit")
    return row


def funded(mode, path, sha):
    need(mode in {"check", "execute"} and digest(PROGRAM) == PROGRAM_SHA, "foreign operation or image")
    need(path.parent == ROOT, "foreign funding path")
    reference, price = read(path, sha)
    plan_ref, plan = read(PLAN)
    need(price["schema"] == "horizon-private-lanek185-retirement-live-funding-v1"
         and price["mode"] == mode and 0 <= time.time() - price["at"] <= 120
         and price["available_home"] >= price["required_home"]
         and price["available_ram"] >= price["required_ram"]
         and price["resource_credit_bytes"] == 0 and price["park_invocation"] == EVIDENCE["IID"]
         and price["plan"] == plan_ref, "missing fresh exact fit")
    need(digest(Path(price["fleet"]["path"])) == price["fleet"]["sha256"], "fleet changed")
    _, event = read(ROOT / "RETIREMENT_READY_AFTER_PARK.json")
    need(event["plan"] == plan_ref and event["custody"] == plan["custody"], "different post-park event")
    if mode == "execute":
        _, prior = read(ROOT / "NATIVE_CUSTODY_CHECK.json")
        need(prior["plan"] == plan_ref and prior["image_sha256"] == PROGRAM_SHA and prior["success"] is True,
             "missing positive custody check for the same plan")
    return reference, plan_ref


def launch(mode, plan_ref):
    _, package = read(ROOT / "package/plan.json", "929fd063b6776b525699f504dd6e83835a34ce6a08f8e690b3c6ff407dd9ea95")
    source = Path(package["source"])
    writable = [source.parent, STATE / "retirements", STATE / "transition.lock",
                Path("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock")]
    properties = [
        "User=root", "Group=root", "NoNewPrivileges=yes", "Restart=no", "ProtectSystem=strict",
        "ProtectHome=read-only", "ReadWritePaths=" + " ".join(map(str, writable)),
        "EnvironmentFile=/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1/credentials.env",
        "CPUQuota=100%", "MemoryMax=1G", "MemorySwapMax=0", "TasksMax=32", "RuntimeMaxSec=4h", "UMask=0077",
    ]
    need(native()["LoadState"] == "not-found", "another owner has the qualified unit")
    args = ["/usr/bin/systemd-run", "--service-type=exec", "--no-block", "--unit=" + UNIT]
    for value in properties:
        args.extend(["-p", value])
    command = "holding-check-retire185-lanek" if mode == "check" else "holding-retire185-lanek"
    args.extend([str(PROGRAM), command, str(PLAN), "--spec-sha256", plan_ref["sha256"], "--self-sha256", PROGRAM_SHA])
    started = time.time()
    subprocess.run(args, check=True)
    return source, started


def wait_for_process():
    for _ in range(150):
        row = native()
        if row.get("MainPID", "0") != "0" and row.get("SubState") == "running":
            need(len(row["InvocationID"]) == 32 and row["MainPID"] == row["ExecMainPID"], "invalid actor")
            pid = int(row["MainPID"])
            fd = os.pidfd_open(pid)
            try:
                proc = Path("/proc") / str(pid)
                need((proc / "exe").samefile(PROGRAM)
                     and (proc / "cgroup").read_text().strip() == "0::/system.slice/" + UNIT,
                     "unexpected execution namespace")
                actor = {"iid": row["InvocationID"], "pid": pid, "native": row,
                         "ticks": int((proc / "stat").read_text().rsplit(") ", 1)[1].split()[19])}
                print(json.dumps(actor), flush=True)
                watch = select.poll()
                watch.register(fd, select.POLLIN)
                watch.poll()
                return actor
            finally:
                os.close(fd)
        time.sleep(0.05)
    raise RuntimeError("qualified process did not reach the observed native dispatch")


def terminal(actor, started):
    messages = []
    for _ in range(30):
        lines = subprocess.check_output(["/usr/bin/journalctl", "-u", UNIT, "--since", "@" + str(int(started)),
                                         "--no-pager", "-o", "json"]).splitlines()
        records = [json.loads(line) for line in lines]
        messages = [r["MESSAGE"] for r in records if r.get("_SYSTEMD_INVOCATION_ID") == actor["iid"]]
        for r in records:
            if (r.get("_PID") == "1" and r.get("UNIT") == UNIT and r.get("INVOCATION_ID") == actor["iid"]
                    and r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448"):
                return r["__REALTIME_TIMESTAMP"], messages
        time.sleep(0.25)
    raise RuntimeError("no clean native terminal for the exact invocation: " + repr(messages[-2:]))


def main(mode, price_path, price_sha):
    price, plan = funded(mode, Path(price_path), price_sha)
    source, started = launch(mode, plan)
    actor = wait_for_process()
    ended, output = terminal(actor, started)
    if mode == "check":
        results = [json.loads(line) for line in output if line.startswith("{")]
        need(len(results) == 1 and results[0]["authenticated_custody_revalidated"] is True
             and results[0]["local_allocated_bytes"] == 66_546_122_752 and results[0]["data_removed"] is False,
             "missing exact native check")
    else:
        _, complete = read(STATE / "retirements/epoch185-lanek-complete.json")
        need(not source.exists() and complete["source_absent"] and complete["quarantine_absent"]
             and complete["retired_physical_bytes"] == 66_546_122_752 and complete["authenticated_custody_revalidated"]
             and complete["whole_readback_before_retirement"], "missing native reclamation")
    result = dict(schema="horizon-185-lanek-native-retirement-dispatch-v1", mode=mode, actor=actor, plan=plan,
                  price=price, image_sha256=PROGRAM_SHA, success=True, end_usec=ended, output=output)
    name = "NATIVE_CUSTODY_CHECK.json" if mode == "check" else "NATIVE_RETIREMENT_EXECUTION.json"
    print(json.dumps(persist(ROOT / name, result)), flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
