"""Observe the status writer and retained verifier for the November 22 HOME-floor recovery."""
import json
import os
from pathlib import Path
import stat
import subprocess

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
STATUS = R / "survivor172-cadence-20261122-v1"
PUBLISHER_IID = "1baf803f31384ddaacb3a291ad9383bc"
VERIFIER_IID = "afcf6cdd1ec0400ea2757f81472987b3"
CANDIDATE = Path("/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN")


def locked_fd(s, pid, path):
    """Match a kernel write lock held by this process to the open file and inode."""
    target = path.lstat()
    s.need(path.resolve(strict=True) == path and stat.S_ISREG(target.st_mode) and
           target.st_uid == target.st_gid == 0 and target.st_nlink == 1, "different consumer lock")
    proc = Path("/proc") / str(pid)
    file_id = f"{os.major(target.st_dev):02x}:{os.minor(target.st_dev):02x}:{target.st_ino}"
    match = ["FLOCK", "ADVISORY", "WRITE", str(pid), file_id, "0", "EOF"]
    for fd in (proc / "fd").iterdir():
        try:
            if os.path.samestat(fd.stat(), target):
                rows = (proc / "fdinfo" / fd.name).read_text().splitlines()
                if any(line.startswith("lock:") and line.split()[2:] == match for line in rows):
                    s.need(os.path.samestat(target, path.lstat()) and os.path.samestat(target, fd.stat()),
                           "status writer lock replaced")
                    return int(fd.name)
        except FileNotFoundError:
            # An unrelated short-lived descriptor can close during enumeration.
            continue
    raise ValueError("writer does not hold the original exclusive consumer lock")


def selected_status(s, fit):
    deployed, _ = s.read(STATUS / "DEPLOYED.json", "80fff053350536011bf779df37f121cad46fda101251ed3295320257c0de4773")
    active = STATUS / "COLD167_STATUS_ACTIVE.json"
    rollback = STATUS / "COLD167_STATUS_ROLLBACK.json"
    if not active.exists() and not rollback.exists():
        return STATUS / "tools", deployed["sources"], PUBLISHER_IID, None
    q, qr = s.read(STATUS / "COLD167_STATUS_QUALIFIED.json",
                   "c9d14b49aece021a26dca2ac7b29786f43fd6921dc6bb1af417901042a1b9846")
    intent, ir = s.read(STATUS / "COLD167_STATUS_INTENT.json")
    previous = intent["old"]
    s.need(previous["unit"] == fit.PUBLISHER and previous["invocation_id"] == PUBLISHER_IID
           and Path(previous["program"]) == STATUS / "tools/status_cycle.py" and intent["qualified"] == qr,
           "foreign prior cadence handoff")
    if not active.exists():
        row, _ = s.read(rollback)
        current = row["restored"]
        s.need(row["intent"] == ir and row["schedule"] == intent["schedule"], "foreign status rollback")
        package, seal_ref = STATUS / "tools", deployed["sources"]
    else:
        row, _ = s.read(active)
        current = row["new"]
        package, seal_ref = STATUS / "tools-cold167", q["package"]
        s.need(seal_ref["sha256"] == "41203635cd5e52237f0c3915ea48ce9c5b062cd1beed4d3414abad5fa3e3f985"
               and row["qualified"] == qr and row["old"] == previous and row["intent"] == ir
               and row["schedule"] == intent["schedule"] and row["admission"] == intent["admission"],
               "foreign status deployment or adoption")
        candidate = R / "epoch167-source-index-rebook-20261122-v1"
        admitted = s.bound(row["admission"], candidate / "ACTUAL_ADMISSION_AND_PROTECTION.json")
        s.need(admitted["epoch"] == 167 and s.iid(admitted["producer_invocation_id"]), "foreign 167 admission")
    s.need(current["unit"] == fit.PUBLISHER and Path(current["program"]) == package / "status_cycle.py"
           and s.iid(current["invocation_id"]) and current["invocation_id"] != PUBLISHER_IID
           and all(current["lock"][k] == previous["lock"][k] for k in ("device","inode","path")),
           "different writer or lock across the cadence handoff")
    return package, seal_ref, current["invocation_id"], current


def registered_status(s, fit):
    _, registration = s.read(fit.READY, "02027e3e35364f64913b34162fde295bfb96b3123a9d9794545ce4e0b1a4e8ba")
    package, seal_ref, iid, adopted = selected_status(s, fit)
    seal = s.bound(seal_ref, package / "deployment-seal-receipt.json")
    program = package / "status_cycle.py"
    s.need(seal["destination"] == str(package), "foreign status deployment")
    member, = (r for r in seal["members"] if r["name"] == program.name)
    fit.binary(program, member["sha256"])
    python = Path("/usr/bin/python3").resolve(strict=True)
    fit.binary(python, "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")

    def owner():
        mgr = s.show(fit.PUBLISHER)
        s.need(mgr["Id"] == fit.PUBLISHER and mgr["InvocationID"] == iid
               and mgr["ActiveState"] == "active" and mgr["SubState"] == "running" and not mgr["Job"]
               and mgr["ControlPID"] == mgr["NRestarts"] == "0", "different status writer invocation")
        pid = int(mgr["MainPID"])
        s.need(pid > 1, "status writer absent")
        proc = Path("/proc") / str(pid)
        _, ticks, group = s.process(pid)
        s.need(group == "0::/system.slice/" + fit.PUBLISHER and s.same_file(proc / "exe", python)
               and (proc / "cmdline").read_bytes().split(b"\0") ==
               [b"/usr/bin/python3", b"-IB", os.fsencode(program), b""], "different live status writer")
        return pid, ticks

    pid, ticks = owner()
    fd = locked_fd(s, pid, fit.LOCK)
    if adopted is not None:
        lock = fit.LOCK.lstat()
        s.need((pid, ticks) == (adopted["pid"], adopted["start_ticks"]) and adopted["lock"] ==
               dict(path=str(fit.LOCK), device=lock.st_dev, inode=lock.st_ino, fd=fd),
               "adopted publisher changed after taking its exclusive lock")
    s.need(owner() == (pid, ticks), "status generation changed during registration")
    return dict(registration=registration, consumer_seal=seal_ref, invocation_id=iid,
                pid=pid, start_ticks=ticks)


def manager_exit(s, unit, iid, reported_at):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    fields = "_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,COMMAND"
    raw = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-ojson", "--output-fields=" + fields,
        "_BOOT_ID=" + boot, "_PID=1", "UNIT=" + unit, "INVOCATION_ID=" + iid], timeout=10)
    rows = [json.loads(line) for line in raw.splitlines()]
    starts = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    exits = [r for r in rows if r.get("MESSAGE_ID") == "98e322203f7a4ed290d09fe03c09fe15"]
    s.need(len(starts) == len(exits) == 1 and all(r["_PID"] == "1" and r["_BOOT_ID"] == boot and
           r["UNIT"] == unit and r["INVOCATION_ID"] == iid for r in rows), "unbound verifier exit")
    end = exits[0]
    s.need(end["COMMAND"] == "ExecStart" and end["EXIT_CODE"] == "exited" and end["EXIT_STATUS"] == "1"
           and int(starts[0]["__MONOTONIC_TIMESTAMP"]) < int(end["__MONOTONIC_TIMESTAMP"])
           and int(starts[0]["__REALTIME_TIMESTAMP"]) // 1_000_000 <= reported_at <=
           int(end["__REALTIME_TIMESTAMP"]) // 1_000_000, "different native verifier result")
    return end


def phase145(s, fit, epoch):
    """Bind the failed same-image retry while its candidate and entire reservation are retained."""
    unit = fit.A145
    mgr = s.show(unit)
    s.need(mgr["Id"] == unit and mgr["InvocationID"] == VERIFIER_IID
           and mgr["ActiveState"] == mgr["SubState"] == "failed" and mgr["ExecMainStatus"] == "1"
           and mgr["Result"] == "exit-code" and not mgr["ControlGroup"] and not mgr["Job"]
           and mgr["MainPID"] == mgr["ControlPID"] == mgr["NRestarts"] == "0"
           and not fit.members(unit), "different retry1 verifier or occupied group")
    state = R / "epoch145-guarded-export-20261121-v1/state" / VERIFIER_IID
    failed, failure = s.read(state / "failed.json", "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366")
    started, recovery = s.read(state / "recovery-started.json", "82532ce3f39356a26d78b2eb07ef32d6a90d604f7537d024ba5e696c42573ceb")
    semantic = R / "epoch145-semantic-continuity-20261121-v1"
    worker, wr = s.read(semantic / "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json",
                        "1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501")
    previous = s.bound(worker["manager"], semantic / "V5F_RETRY1_ACTUAL_MANAGER.json")
    s.need({f.name for f in state.iterdir()} == {"failed.json", "recovery-started.json"}
           and failed["iid"] == started["iid"] == worker["invocation_id"] == previous["new"]["InvocationID"] == VERIFIER_IID
           and worker["start"] == recovery and worker["resource_credit_bytes"] == 0
           and started["image"] == "016f1beab41795dae2bbaa1cef5173773eeafae617a5f5db92ebd4aaa1887c21"
           and not started["r2_mutations"] and failed["error"].rstrip().endswith("ValueError: unregistered replay process 429808"),
           "different retry1 evidence or verification phase")
    s.need(Path(started["file"]) == CANDIDATE == CANDIDATE.resolve(strict=True), "different epoch 145 candidate")
    m = CANDIDATE.lstat()
    identity = dict(bytes=m.st_size, ctime_ns=m.st_ctime_ns, device=m.st_dev, gid=m.st_gid, inode=m.st_ino,
                    mode=m.st_mode, mtime_ns=m.st_mtime_ns, uid=m.st_uid)
    s.need(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_size == 105610995833
           and identity == started["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"],
           "sealed verifier candidate replaced or changed")
    end = manager_exit(s, unit, VERIFIER_IID, failed["at"])
    s.need(s.show(unit) == mgr and not fit.members(unit), "verifier generation changed during recovery check")
    result = {k: mgr[k] for k in ("Id", "ActiveState", "SubState", "InvocationID", "MainPID")}
    return dict(result, failure=failure, recovery=recovery, candidate=identity, manager_exit=end,
                retry_worker=wr, source_checkpoint_exists=False, resource_credit_bytes=0)
