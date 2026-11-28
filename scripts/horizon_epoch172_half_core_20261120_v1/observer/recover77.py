"""Recover the scheduled 13:48 observer under the original service and lock."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import status_cycle as c
import cutover77 as h
import transition_v77 as handoff


def stopped(old):
    iid=old["invocation_id"]
    state=h.state(h.WRITER,"InvocationID","ActiveState","SubState","Result","MainPID","ControlPID","Job","ExecMainStatus")
    c.need(iid=="c1386af693324087b1a4e82a6449fb54" and state["InvocationID"]==iid
           and state["ActiveState"]==state["SubState"]=="failed" and state["Result"]=="exit-code"
           and state["MainPID"]==state["ControlPID"]=="0" and state["ExecMainStatus"]=="1" and not state["Job"],
           "different failed V76 writer")
    proc=Path("/proc")/str(old["pid"])
    c.need(not proc.exists() or c.owners.ticks(old["pid"])!=old["start_ticks"],"old writer still running")
    checks=[
        ["_PID=1","_UID=0","UNIT="+h.WRITER,"INVOCATION_ID="+iid,"MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15",
         "COMMAND=ExecStart","EXIT_CODE=exited","EXIT_STATUS=1"],
        ["_SYSTEMD_UNIT="+h.WRITER,"_SYSTEMD_INVOCATION_ID="+iid,"_PID="+str(old["pid"]),
         "MESSAGE=ValueError: wrong sample predecessor or cadence"],
    ]
    cursors=[]
    for fields in checks:
        lines=h.command("/usr/bin/journalctl","-b","-q","--no-pager","-o","json",*fields).splitlines()
        c.need(len(lines)==1,"missing original manager exit or exact V76 failure")
        cursors.append(json.loads(lines[0])["__CURSOR"])
    return cursors


def recover(digest,apply):
    c.need(os.geteuid()==0 and HERE==h.NEW and c.entry()==h.member(HERE,Path(__file__).name)
           and c.entry()["sha256"]==digest,"different recovery package")
    with h.BOOKING_LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if h.ACTIVE.exists():
            current=h.doc(h.ACTIVE)
            h.owner(current["new"],HERE)
            c.need(current["ready"]==h.ref(h.READY),"foreign active writer")
            return h.ref(h.ACTIVE)
        selection=c.checked(c.checked(handoff.final.SELECTED)["selection"])
        head=selection["fleet"]
        fleet=c.checked(head)
        ready=handoff.ready(vars(c),head,c.entry())
        old=c.checked(ready["old_owner"])["new"]
        events=stopped(old)
        observed=c.checked(ready["completed_sample"])
        cfg=handoff.final.effective(c.sealed(ready["config"]))
        c.check_sample(fleet,observed,cfg)
        n=c.names(cfg["not_before_utc"])
        c.need(not (n["out"]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json").exists() and not n["statuses"].exists(),
               "original writer already produced a status batch")
        roster=h.endpoints(fleet)
        if not apply:
            return dict(sample=ready["completed_sample"],archive=handoff.final.ARCHIVE,owners=sorted(roster["producers"]))
        c.durable(handoff.final.ROOT/"OBSERVER_AND_WRITER_HANDOFF.json",dict(exit_cursors=events,ready=ready,roster=roster))
        c.durable(h.READY,ready)
        directory=h.SYSTEMD_DIRECTORY/(h.WRITER+".d")
        previous=max(directory.glob("*-v76-*.conf"),key=lambda path:path.name)
        raw=previous.read_bytes()
        c.need(raw.count(os.fsencode(h.OLD))==1,"different incumbent definition")
        repl=raw.replace(os.fsencode(h.OLD),os.fsencode(HERE))
        dropin=directory/("z"+previous.name.replace("-v76-","-v77-"))
        if dropin.exists():
            c.need(dropin.read_bytes()==repl,"another recovery definition exists")
        else:
            h.private_write(dropin,repl,0o644)
        h.systemctl("daemon-reload")
        c.need(str(HERE/"status_cycle.py") in h.state(h.WRITER,"ExecStart")["ExecStart"] and not c.timer_names()
               and h.endpoints(fleet)==roster,"protected fleet or clock changed")
        stopped(old)
        h.systemctl("start",h.WRITER)
        return dict(started=True,observer=ready["completed_sample"])


if __name__=="__main__":
    args=argparse.ArgumentParser(description=__doc__)
    args.add_argument("seal")
    args.add_argument("--apply",action="store_true")
    parsed=args.parse_args()
    print(json.dumps(recover(parsed.seal,parsed.apply),sort_keys=True))
