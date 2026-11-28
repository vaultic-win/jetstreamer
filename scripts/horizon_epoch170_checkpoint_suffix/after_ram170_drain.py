"""Drain only the third RAM guard after the complete private segment is in custody."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time

from after_ram170_scope import ROOT, PREPARATION
import following_prepare as prep

IID = "5f7a0dc3b03346b7b7cfa17a51e150aa"
TIMER_IID = "61ac56a76759428fb6857bf60cae69ac"
UNIT = "horizon-qualify-170-from-73760367-ram-20261128-v3.service"
GUARD = UNIT.replace("-qualify-", "-guard-")
TIMER = GUARD.replace(".service", ".timer")
CGROUP = Path("/sys/fs/cgroup/system.slice")
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")


def properties(unit, fields):
    result = subprocess.run(["/usr/bin/systemctl", "show", "--all", "--property=" + fields, "--", unit],
                            capture_output=True, text=True)
    prep.need(result.returncode in (0, 4), result.stderr)
    row = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    prep.need(row.get("Id") == unit and not row["Job"], "unexpected or transitioning " + unit)
    return row


def idle_service(unit):
    row = properties(unit, "Id,ActiveState,Job,MainPID,ControlPID,ControlGroup")
    prep.need(row["ActiveState"] in ("inactive","failed") and row["MainPID"] == row["ControlPID"] == "0"
              and not row["ControlGroup"] and not (CGROUP / unit).exists(), "producer or guard still active " + unit)


def clean_custody():
    source = prep.read(PREPARATION)
    release_ref = source["predecessor_release"]
    release = prep.read(release_ref)
    actor = prep.read(release["actor"])
    scope = prep.read(release["interface"])
    prep.need(actor["unit"] == scope["expected_producer_unit"] == UNIT and actor["producer_invocation_id"] == IID
              and release["producer_invocation_id"] == IID and release["guard_timer_invocation_id"] == TIMER_IID
              and release_ref["sha256"] == "bbbd90b4e78b50abd57e2dac56bf32c9384981a561d85bcf1b3b7b8c46725459",
              "different released RAM producer")
    idle_service(UNIT)
    custody_ref = prep.reference(ROOT / "THIRD_TERMINAL_AND_CUSTODY.json")
    custody = prep.read(custody_ref)
    report = prep.read(custody["comparison"])
    native = prep.read(custody["native_producer"]["pid1"])
    closed = report["evidence"]
    segment = closed["closed_segment"]
    state = native["properties"]
    prep.need(custody["comparison"]["path"] == str(ROOT / "THIRD_CLOSED_COMPARISON.json")
              and report["release"] == native["release"] == release_ref and native["actor"] == actor
              and (state["Id"],state["InvocationID"],state["ExecMainPID"]) == (UNIT,IID,str(actor["producer_pid"]))
              and (state["MainPID"],state["ControlPID"],state["Result"],state["ExecMainCode"],state["ExecMainStatus"])
              == ("0","0","success","1","0") and closed["pid1_exit"]["native"] == state
              and closed["comparison"] == "closed" and report["checkpoints"][-1]["slot"] == 73_766_969
              and report["checkpoints"][-1] == custody["actual_terminal"] and custody["archive"] == segment
              and custody["staged_following"] == PREPARATION and not custody["archive_publication_authorized"],
              "different or unsuccessful RAM closure")
    archive = Path(segment["path"])
    st = archive.lstat()
    ident = [st.st_dev, st.st_ino, st.st_size, *divmod(st.st_mtime_ns, 10**9), *divmod(st.st_ctime_ns, 10**9)]
    prep.need(archive == Path(scope["run"]) / "ledger/epoch-170.diagnostic.jet" and archive.resolve(strict=True) == archive
              and st.st_nlink == 1 and ident == segment["identity"] and prep.read(segment["manifest"])["archive_sha256"] == segment["sha256"],
              "custodied archive or manifest changed")
    progress = prep.read(dict(path=str(Path(release_ref["path"]).with_name("FIRST_PROTECTED_PROGRESS.json")),
                              sha256="142dd34052a7377936fdeb140d79c14de9889d0be23f67fc1ca89c1c51b5adcb"))
    prep.need(progress["producer_invocation_id"] == IID and progress["actor"] == release["actor"]
              and progress["release"] == release_ref, "unbound scratch namespace")
    return scope, release_ref, release, custody_ref, progress["worker"]["scratch_mount"]


def timer(scope, grant):
    idle_service(UNIT)
    row = properties(TIMER, "Id,ActiveState,SubState,Job,InvocationID,Triggers")
    if row["ActiveState"] == "inactive":
        return False
    guard = properties(GUARD, "Id,Job,TriggeredBy,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,Restart")
    plan_ref = grant["guard_plan"]
    plan = prep.read(plan_ref)
    image = Path(scope["guard_seal"]["path"]).with_name("guard")
    expected = f"argv[]={image} {plan_ref['path']} --plan-sha256 {plan_ref['sha256']} --self-sha256 {scope['guard_sha']} ;"
    prep.need(row["ActiveState"] == "active" and row["SubState"] in ("waiting", "running")
              and row["InvocationID"] == grant["guard_timer_invocation_id"] == TIMER_IID
              and row["Triggers"] == GUARD and guard["TriggeredBy"] == TIMER and guard["Restart"] == "no"
              and (guard["MemoryMax"],guard["MemorySwapMax"],guard["CPUQuotaPerSecUSec"]) == (str(1 << 30),"0","1s")
              and expected in guard["ExecStart"] and prep.reference(image)["sha256"] == scope["guard_sha"]
              and plan["unit"] == UNIT and plan["invocation_id"] == IID and plan["receipt_directory"] == scope["guard_receipts"],
              "different RAM guard timer, image, plan or caps")
    return True


def scratch_drained(scratch, scope):
    path = Path(scratch["path"])
    prep.need(path == Path(scope["run"]) / "scratch" and path.resolve(strict=True) == path
              and path.stat().st_dev == Path("/home/sol").stat().st_dev != scratch["device"]
              and scratch["bytes"] == 40 << 30 and not any(path.iterdir()), "host RAM workspace has remaining payload")
    # A private namespace can outlive its worker if another process retains it.
    # Inspect a representative of each live namespace; ignore PIDs that exited during the lookup.
    seen = set()
    for process in Path("/proc").glob("[0-9]*"):
        try:
            namespace = (process / "ns/mnt").stat()
            identity = (namespace.st_dev, namespace.st_ino)
            if identity in seen:
                continue
            info = (process / "mountinfo").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        for line in info.splitlines():
            fields = line.split(" - ", 1)[0].split()
            device = fields[2].split(":")
            mounted = os.makedev(int(device[0]), int(device[1]))
            prep.need(not (fields[4] == str(path) and mounted == scratch["device"]),
                      "original private tmpfs is still projected in a live mount namespace")
        seen.add(identity)
    prep.need(seen, "no mount-namespace observations")
    return {"source":scratch, "host_device":path.stat().st_dev, "live_namespaces_checked":len(seen),
            "original_mount_present":False, "host_directory_empty":True}


def run():
    prep.need(os.geteuid() == 0, "native guard handback requires root")
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        scope, release_ref, grant, custody_ref, scratch = clean_custody()
        binding = dict(producer_invocation=IID, producer=UNIT, timer=TIMER, timer_invocation=TIMER_IID,
                       guard=GUARD, guard_plan=grant["guard_plan"], release=release_ref, custody=custody_ref)
        intent_path = ROOT / "THIRD_GUARD_DRAIN_INTENT.json"
        active = timer(scope, grant)
        prep.need(active or intent_path.exists(), "guard already inactive without a bound drain intent")
        intent = prep.save(intent_path, binding)
        if active:
            prep.need(timer(scope, grant), "guard changed immediately before handback")
            subprocess.run(["/usr/bin/systemctl","stop","--",TIMER],check=True)
        deadline = time.monotonic() + 45
        while True:
            try:
                prep.need(not timer(scope, grant), "RAM guard timer is still active")
                idle_service(GUARD)
                break
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.15)
        mount = scratch_drained(scratch, scope)
        path = ROOT / "THIRD_GUARD_DRAIN.json"
        if path.exists():
            ref = prep.reference(path)
            saved = prep.read(ref)
            prep.need(all(saved[k] == value for k,value in binding.items()) and saved["intent"] == intent
                      and saved["scratch"]["source"] == scratch and saved["scratch_released"]
                      and saved["producer_and_guard_drained"] and not saved["resource_credit_bytes"],
                      "different existing drain")
            return ref
        return prep.save(path,dict(**binding,intent=intent,scratch=mount,scratch_released=True,
                                   producer_and_guard_drained=True,resource_credit_bytes=0,publication_authorized=False))


if __name__ == "__main__":
    print(json.dumps(run()))
