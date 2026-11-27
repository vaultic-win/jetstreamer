"""Preserve the drained epoch 143 gate attempt and reopen its original paths."""
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-first-hourly-20261127-v1")
RUN = Path("/home/sol/.jetstreamer-private") / RT.name
IID = "fa915d8326a34b589238d55833b3e846"
GUARD_IID = "b53c92166a354c73ad2b8518cfda8b34"
UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
GUARD = "horizon-guard-143-first-hourly-20261127-v1"
ASSEMBLY = "horizon-assemble-168-private-20261127-v1.service"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
FAILED = RT / f"failed-{IID}"
OLD_RUN = RUN.with_name(f"{RUN.name}.failed-{IID}")
DISPATCH = Path("/home/sol/.jetstreamer-private/epoch143-normal-entry-20261126.nIp1iDnD") / (
    "dispatch-first-hourly143-v2/NATIVE_LAUNCH_1795803576572557062.json"
)
SAMPLE = f"sample-{GUARD_IID}.json"


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path), "sha256": digest(path)}


def put(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    flush(path.parent)
    return ref(path)


def flush(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def show(unit):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "--all", "-p",
         "Id,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,LoadState", "--", unit],
        text=True, capture_output=True, timeout=10,
    )
    need(result.returncode in (0, 4), f"cannot read native state for {unit}")
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def journal(unit, iid):
    raw = subprocess.check_output(
        ["/usr/bin/journalctl", "-b", "--quiet", "--no-pager", "-o", "json", "_PID=1", "_UID=0",
         "UNIT=" + unit, "INVOCATION_ID=" + iid], text=True, timeout=15,
    )
    return [json.loads(line) for line in raw.splitlines()]


def locate(original, archived):
    present = [p for p in (original, archived) if os.path.lexists(p)]
    need(len(present) == 1 and present[0].resolve(strict=True) == present[0],
         f"ambiguous failed-attempt evidence for {original}")
    return present[0]


def move(original, archived):
    if locate(original, archived) == original:
        code = ctypes.CDLL(None, use_errno=True).renameat2(
            -100, os.fsencode(original), -100, os.fsencode(archived), 1)
        if code != 0:
            raise OSError(ctypes.get_errno(), f"archive failed-attempt path {original}")
        flush(original.parent)
        flush(archived.parent)


def main():
    need(os.geteuid() == 0, "reconciliation requires root")
    os.umask(0o077)
    with LOCK.open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (FAILED / "RECONCILED.json").is_file():
            print(json.dumps(ref(FAILED / "RECONCILED.json")))
            return
        state = {u: show(u) for u in (UNIT, GUARD+".timer", GUARD+".service", ASSEMBLY)}
        for u, row in state.items():
            need(row["Id"] == u and row["ActiveState"] == "inactive" and not row["Job"]
                 and row.get("MainPID", "0") == row.get("ControlPID", "0") == "0"
                 and not (Path("/sys/fs/cgroup/system.slice") / u).exists(),
                 f"native owner or job still present: {u}")
        need(not any((RT/p).exists() for p in ("HELD_OWNER.json", "POST_GUARD_SCREEN.json", "barrier/allow")),
             "the failed gate was released or its receipt scope changed")
        namespaces = set()
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                # Kernel threads and completed processes have no user mount owner.
                if not (proc/"cmdline").read_bytes():
                    continue
                cookie = (proc/"ns/mnt").stat().st_ino
                if cookie in namespaces:
                    continue
                rows = (proc/"mountinfo").read_text().splitlines()
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError as error:
                if error.errno != errno.EINVAL:
                    raise
                try:
                    task = (proc/"stat").read_text().rsplit(") ", 1)[1].split()
                except FileNotFoundError:
                    continue
                need(task[0] in ("Z", "X") or int(task[6]) & 0x4,
                     f"unavailable mountinfo for a live task {proc}")
                continue
            need(not any("/run/horizon143-first-hourly/" in row or f" {RUN}/" in row for row in rows),
                 f"failed launch still has namespace mounts in {proc}")
            namespaces.add(cookie)
        FAILED.mkdir(mode=0o700, exist_ok=True)
        need(FAILED.resolve() == FAILED and FAILED.stat().st_uid == 0 and FAILED.stat().st_mode & 0o777 == 0o700,
             "unsafe failed gate archive")
        items = [(RT/name, FAILED/name) for name in
                 ("PRESTART_SCREEN.json", "ACTUAL_GUARD_PLAN.json", "guard-receipts", "barrier")]
        run = locate(RUN, OLD_RUN)
        plan = locate(*items[1])
        receipts = locate(*items[2])
        barrier = locate(*items[3])
        need(set(p.relative_to(run).as_posix() for p in run.rglob("*"))
             == {"ledger", "ledger/genesis.tar.bz2", "private", "scratch"}
             and (run/"ledger/genesis.tar.bz2").stat().st_size == 0 and not list(barrier.iterdir())
             and {p.name for p in receipts.iterdir()} == {SAMPLE}, "unexpected earlier replay output")
        first = json.loads((receipts/SAMPLE).read_bytes())
        need(first["producer_invocation_id"] == IID and first["guard_invocation_id"] == GUARD_IID
             and first["plan_sha256"] == digest(plan) and first["producer_stop_enabled"] and not first["workers"]
             and first["trip_reason"] is first["root_physical_observation_error"] is first["worker_observation_error"] is None,
             "other first guard scope or actual guard trip")
        launch = json.loads(DISPATCH.read_bytes())
        old_booking = launch["booking"]
        need(launch["returncode"] == 1 and IID in launch["stderr"]
             and old_booking["sha256"] == digest(Path(old_booking["path"]))
             and json.loads(Path(old_booking["path"]).read_bytes())["latest_start_unix_seconds"] < time.time(),
             "failed booking does not bind the expired invocation")
        evidence = FAILED/"PID1_TERMINALS.json"
        if not evidence.exists():
            rows = {"producer": journal(UNIT, IID), "guard": journal(GUARD+".service", GUARD_IID)}
            need(all(any(x.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448" for x in seq)
                     for seq in rows.values()), "missing clean PID1 terminal event")
            put(evidence, rows)
        for old, new in items:
            move(old, new)
        move(RUN, OLD_RUN)
        result = {"schema": "horizon-epoch143-unreleased-gate-reconciled-v1", "failed_invocation": IID,
                  "failed_launch": ref(DISPATCH), "expired_booking": old_booking, "pid1": ref(evidence),
                  "guard_plan": ref(FAILED/"ACTUAL_GUARD_PLAN.json"),
                  "guard_sample": ref(FAILED/"guard-receipts"/SAMPLE),
                  "prestart_screen": ref(FAILED/"PRESTART_SCREEN.json"), "failed_HOME_tree": str(OLD_RUN),
                  "native": state, "release_absent": True, "archive_created": False, "resource_credit_bytes": 0,
                  "reconciled_unix_seconds": int(time.time())}
        print(json.dumps(put(FAILED/"RECONCILED.json", result)))


if __name__ == "__main__":
    main()
