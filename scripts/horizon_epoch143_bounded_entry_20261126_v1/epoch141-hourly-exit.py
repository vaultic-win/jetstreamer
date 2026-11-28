"""Pin the first hourly epoch 141 unit and capture its native exit before collection."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import sys
import time

import dbus

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch141-first-hourly-20261127-v1")
DEST = ROOT/"terminal-capture-v1"
UNIT = "horizon-qualify-141-first-hourly-20261127-v1.service"
IID = "e842fa3c9da04f16a8effceb9224016b"
FIELDS = ("Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,"
          "ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,RuntimeMaxUSec,Result,CollectMode")
spec = importlib.util.spec_from_file_location("suffix", Path(__file__).with_name("epoch140-accept-suffix.py"))
suffix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suffix)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def frozen():
    owner, owner_ref = suffix.read(ROOT/"HELD_OWNER.json", 0)
    progress, progress_ref = suffix.read(ROOT/"FIRST_PROTECTED_PROGRESS.json", 0)
    fit, fit_ref = suffix.read(ROOT/"POST_GUARD_SCREEN.json", 0)
    time_change, extension = suffix.read(ROOT/"TIME_CONTINUATION_APPLIED_131808.json", 0)
    permit, _ = suffix.file_ref(ROOT/"barrier/allow", 0)
    expect, expect_ref = suffix.read(ROOT/"first-close-expectations-v1/HOURLY_CLOSE_EXPECTATIONS.json", 0)
    row = expect["intervals"][0]
    native = time_change["native_after"]["services"][UNIT]
    require(expect_ref["sha256"] == "cd8c503cbd7d86eabc04937303f80aeffa4a55c770f3384cfb059df1dfb4ef7f"
            and extension["sha256"] == "e5b0de96453f5989e73e936e242a12fa15879b864c94d10933017d2ee6215622"
            and (owner_ref, progress_ref) == (row["held_owner"], row["first_protected_output"])
            and owner["unit"] == UNIT and owner["producer_invocation_id"] == progress["producer_invocation_id"]
            == fit["held_invocation"] == time_change["invocation_id"] == row["producer_invocation_id"] == IID
            and fit_ref == owner["post_guard_fit"] and fit["memory_fits"] and fit["disk_fits"]
            and progress["held_owner"] == owner_ref and progress["producer_pid"] == owner["producer_pid"]
            and progress["transactions"] > 0 and owner["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            and permit["sha256"] == hashlib.sha256(IID.encode()).hexdigest()
            and native["RuntimeMaxUSec"] == "6h 35min 30s" and time_change["stable_worker_identities"],
            "epoch 141 release, expectations or time extension changed")
    return owner, dict(actor=owner_ref, release=permit, postguard=fit_ref, first_progress=progress_ref,
                       time_extension=extension, expectations=expect_ref), native


def capture(unit, actor, bindings, expected, destination, mode, *, epoch=141):
    pid = actor["producer_pid"]
    iid = actor["producer_invocation_id"]
    suffix.AUTHORITY = destination
    bus = dbus.SystemBus(private=True)
    manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"),
                             "org.freedesktop.systemd1.Manager")
    manager.RefUnit(unit)
    try:
        fd = os.pidfd_open(pid)
        try:
            live = suffix.native_properties(unit, FIELDS)
            ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            require(ticks == actor["start_ticks"] and live["Id"] == unit and live["ActiveState"] == "active"
                    and live["InvocationID"] == iid and int(live["MainPID"]) == int(live["ExecMainPID"]) == pid
                    and live["CollectMode"] == "inactive" and all(live[k] == expected[k] for k in
                    ("RuntimeMaxUSec","ExecMainStartTimestampMonotonic")) and not select.select([fd], [], [], 0)[0],
                    "native producer changed before pidfd attachment")
            arm = dict(schema=f"horizon-{epoch}-first-hourly-native-exit-armed-v1", timestamp=time.time(),
                       actor=actor, bindings=bindings, unit_reference_held=True, pidfd_bound=True, native=live,
                       watcher_invocation=os.environ.get("INVOCATION_ID"), publication_authorized=False)
            if mode == "check":
                return arm
            armed_path = destination/"ARMED.json"
            if not armed_path.exists():
                suffix.persist(armed_path, arm)
            old, arm_ref = suffix.read(armed_path, 0)
            require(all(old[k] == arm[k] for k in ("actor", "bindings", "unit_reference_held", "pidfd_bound",
                                                 "watcher_invocation")), "different watcher already armed")
            select.select([fd], [], [])
            for _ in range(100):
                end = suffix.native_properties(unit, FIELDS)
                require(end["Id"] == unit and end["InvocationID"] == iid and int(end["ExecMainPID"]) == pid
                        and end["ExecMainStartTimestampMonotonic"] == live["ExecMainStartTimestampMonotonic"],
                        "foreign terminal producer")
                if (end["ActiveState"] in ("inactive", "failed") and end["MainPID"] == end["ControlPID"] == "0"
                        and int(end["ExecMainExitTimestampMonotonic"]) > int(live["ExecMainStartTimestampMonotonic"])):
                    receipt = dict(schema=f"horizon-{epoch}-first-hourly-native-exit-v1", actor=actor, bindings=bindings,
                                   armed=arm_ref, properties=end, timestamp=time.time(), publication_authorized=False)
                    suffix.persist(destination/"PID1_EXIT.json", receipt)
                    return receipt
                time.sleep(0.1)
            raise ValueError("PID1 did not settle after producer exit")
        finally:
            os.close(fd)
    finally:
        manager.UnrefUnit(unit)
        bus.close()


if __name__ == "__main__":
    require(sys.argv[1:] in (["check"], ["capture"]), "expected check or capture")
    actor, bindings, native = frozen()
    print(json.dumps(capture(UNIT, actor, bindings, native, DEST, sys.argv[1])), flush=True)
