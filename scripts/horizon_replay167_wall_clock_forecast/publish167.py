"""Run under the singleton cadence consumer's lock at the exact 20:49 fleet handoff."""
import datetime as dt
import fcntl
import os
from pathlib import Path
import sys

import replay167_event as event
from evidence import BASE, bound, checked, content, digest, durable, ensure_dir, lock, need, utc
from owners import show
from status import Storage, body, follow_event

CONTROL = "horizon-archive-status-cadence-after172-20261120-v1.service"
NEXT_TIMER = "horizon-observer-root211959-live166167170-20261120-v1.timer"
DUE = "2026-11-20T21:19:59Z"

def owner_fence(intent):
    fleet = checked(event.FLEET)
    timer = show(NEXT_TIMER,("ActiveState",))["ActiveState"]
    need(fleet["sole_next_timer"] == NEXT_TIMER and timer == "active" and dt.datetime.now(dt.timezone.utc) < utc(DUE),
         "existing routine cadence has priority")
    consumer = show(CONTROL,("MainPID","ExecStart"))
    pkg = Path(__file__).resolve().parent
    pid = int(consumer["MainPID"])
    need(str(pkg/"consume") in consumer["ExecStart"] and os.fsencode(pkg/"consume") in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"),
         "unqualified singleton status owner")
    lockfile = BASE/"stable-cadence-controller-20261120-v1/consumer.lock"
    need(Path(f"/proc/{pid}/fd/9").samefile(lockfile), "wrong singleton lock")
    # The persistent parent acquired flock on fd 9 before invoking this child.
    with lockfile.open("rb") as f:
        try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: raise ValueError("singleton lock has no owner")
    for row in fleet["actual_executing_replays"]:
        n = row["unit"]
        now = show(n["Id"],("InvocationID","MainPID","ActiveState","SubState","NRestarts"))
        need(all(now[k]==n[k] for k in now),"replay owner moved")
    cfg = next(r for r in fleet["actual_executing_replays"] if r["scratch_path"]==str(Path(intent["archive_sample"]["path"]).parent.parent/"scratch"))
    guard = checked(cfg["guard_protection"])
    need(guard["epoch"] == 167 and guard["timer_invocation_id"] == intent["native_identity"][1]["InvocationID"], "foreign 167 guard protection")
    actual = show(guard["timer_unit"],("InvocationID","ActiveState"))
    need(actual["ActiveState"] == "active" and actual["InvocationID"] == intent["native_identity"][1]["InvocationID"], "167 guard moved")
    a = intent["archive_sample"]
    archive = Path(a["path"])
    m = archive.lstat()
    need((m.st_dev,m.st_ino)==(a["device"],a["inode"]) and m.st_size>=a["size"] and archive.samefile(a["bound_producer_fds"][0]),
         "167 archive no longer belongs to the captured native producer")

def main(fleet,sha):
    need(os.geteuid()==0 and {"path":fleet,"sha256":sha}==event.FLEET,"foreign 167 correction anchor")
    os.umask(0o077)
    s=Storage()
    cohort=checked(event.FLEET)["authenticated_status_audit"]
    ensure_dir(event.EVENT)
    fd=lock(event.EVENT/"writer.lock")
    try:
        with (Path(cohort["path"]).parent/"cycle.lock").open("rb") as cycle_lock:
            fcntl.flock(cycle_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            proposal=event.expected()
            owner_fence(proposal)
            tag,raw=s.get(167)
            intent=event.EVENT/"INTENT.json"
            result=event.EVENT/"RECEIPT.json"
            expected=body(proposal["after_status"])
            if result.exists():
                event.verify_event(content(result),proposal,tag,raw)
                return
            if not intent.exists():
                need(tag==proposal["before_etag"] and digest(raw)==proposal["before_sha256"] and raw==body(proposal["before_status"]),"authenticated 167 object changed")
            durable(intent,proposal)
            if (tag,digest(raw))==(proposal["before_etag"],proposal["before_sha256"]):
                owner_fence(proposal)
                sent=s.put(167,tag,expected)
                tag,raw=s.get(167)
                need(tag==sent,"167 PUT/readback ETag mismatch")
            need(raw==expected and digest(raw)==proposal["after_sha256"],"167 conditional outcome differs")
            receipt=dict(proposal, after_etag=tag, authenticated_readback=True, verified_at_utc=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            event.verify_event(receipt,proposal,tag,raw)
            durable(result,receipt)
            need(follow_event(167,event.PREVIOUS,tag,raw)==(bound(result),receipt),"new owner cannot follow authenticated event")
    finally:
        os.close(fd)

if __name__=="__main__":
    main(*sys.argv[1:])
