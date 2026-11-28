"""Join the corrected 159 grant and terminal to the original 145 donor inspection."""
import json
from pathlib import Path
import re

R = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch159-vote-feature-reference-20261123-v1")
UNIT = "horizon-epoch159-vote-feature-reference-20261123-v1.service"
GROUP = Path("/sys/fs/cgroup/system.slice") / UNIT


def snapshot(donor):
    need, bound, cmd = (donor[k] for k in ("need","bound","command"))
    props = dict(row.split("=",1) for row in cmd("/usr/bin/systemctl","show",
        "-p","Id,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ControlPID,NRestarts",UNIT).splitlines())
    need(props["Id"] == UNIT and props["ActiveState"] in ("inactive","failed") and props["SubState"] in ("dead","failed")
         and props["MainPID"] == props["ControlPID"] == props["NRestarts"] == "0" and not props["Job"]
         and (not GROUP.exists() or not (GROUP/"cgroup.procs").read_text().strip()), "epoch 159 feature worker or job present")
    attempt = R/"attempt-v1"
    if not (R/"ADMISSION.json").exists():
        need(not props["InvocationID"] and not (R/"DISPATCH_INTENT.json").exists() and not attempt.exists(),
             "incomplete epoch 159 admission")
        return {"unit":UNIT, "stage":"unclaimed"}
    grant, gh = bound(R/"ADMISSION.json")
    intent, ih = bound(R/"DISPATCH_INTENT.json")
    started, sh = bound(attempt/"start.json")
    terminal, th = bound(attempt/"driver-exit.json")
    iid = started["iid"]
    need(grant["actual_grant"] is True and grant["unit"] == intent["unit"] == started["unit"] == UNIT
         and intent["grant"] == started["grant"] == gh and re.fullmatch("[a-f0-9]{32}",iid)
         and iid == terminal["iid"] and props["InvocationID"] in ("",iid), "unsettled epoch 159 grant")
    if terminal["code"] == 0:
        end, eh = bound(attempt/"success.json")
        need(end["outcome"] == terminal["retained"]["outcome.json"], "different successful 159 outcome")
    else:
        end, eh = bound(attempt/"service-failure.json")
        need(end["grant"] == gh, "different failed 159 grant")
    need(end["iid"] == iid and end["utc"] >= terminal["utc"], "different 159 terminal generation")
    journal = cmd("/usr/bin/journalctl","-q","--no-pager","-o","json","_PID=1","UNIT="+UNIT,"INVOCATION_ID="+iid)
    exits = [r for r in map(json.loads,journal.splitlines()) if r.get("MESSAGE_ID") in
             ("d9b373ed55a64feb8242e02dbe79a49c","7ad2d189f7e94e70a38c781354912448")]
    need(len(exits)==1 and exits[0]["MESSAGE_ID"] == ("7ad2d189f7e94e70a38c781354912448" if terminal["code"]==0
         else "d9b373ed55a64feb8242e02dbe79a49c"), "missing 159 manager terminal")
    for name, digest in terminal["retained"].items():
        need(re.fullmatch(r"[a-z0-9-]+\.json",name), "unexpected 159 evidence")
        bound(attempt/"retained"/name,digest)
    for name in ("evidence","scratch"):
        img=attempt/(name+".ext4")
        need(not cmd("/usr/sbin/losetup","-j",str(img)), "159 still has a loop device")
        identity,_=bound(attempt/(name+"-identity.json"))
        if img.exists():
            stat=img.lstat()
            need((stat.st_dev,stat.st_ino,stat.st_size)==(identity["dev"],identity["ino"],identity["size"])
                 and stat.st_blocks*512>=stat.st_size, "unaccounted 159 image")
        else:
            retired,_=bound(attempt/"scratch-retired.json")
            need(name=="scratch" and retired["iid"]==iid and retired["dev"]==identity["dev"]
                 and retired["ino"]==identity["ino"], "missing 159 image settlement")
    return {"unit":UNIT, "stage":"drained", "iid":iid, "grant":gh, "intent":ih, "start":sh, "terminal":th,
            "outcome":eh, "manager_exit_cursor":exits[0]["__CURSOR"], "resource_credit_bytes":0}
