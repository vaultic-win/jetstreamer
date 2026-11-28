"""Retire exactly the three stopped producer generations' guard timers after native proof."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
CAD = R / "epoch168-witness-incident-20261121-v1/publisher-v1"
SEAL = "5ddfc665fc068ec14f2adb6082dcedee8f0ffe2630a45dc5a291fa7bdeeefcb5"
D = R / "incident-replay-fit-20261121-v1"
Q = D / "ORIGINAL_GUARD_TIMERS_RETIRED.json"

def verified(path, sha):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_mode & 0o022 or
        path.resolve(strict=True) != path or st.st_size > 4 << 20):
        raise ValueError("untrusted " + str(path))
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError("different " + str(path))
    return raw

def load_package(package, seal):
    record=json.loads(verified(package/"deployment-seal-receipt.json",seal))
    names = {x["name"] for x in record["members"] if x["name"].endswith(".py")}
    if (record["destination"] != str(package) or package.stat().st_uid or
        package.stat().st_mode & 0o022 or names != {p.name for p in package.glob("*.py")} or
        any(p.is_dir() or p.is_symlink() or p.suffix in (".pyc",".so") for p in package.iterdir())):
        raise ValueError("untrusted module directory")
    for x in record["members"]:
        if x["name"] in names:
            verified(package/x["name"], x["sha256"])

def native(unit):
    props="Id,InvocationID,MainPID,ControlPID,LoadState,SubState,ActiveState,Job,Triggers"
    out=subprocess.run(["/usr/bin/systemctl","show","-p",props,unit],capture_output=True,text=True)
    v=dict(line.split("=",1) for line in out.stdout.splitlines())
    if out.returncode and not (out.returncode == 4 and v.get("LoadState") == "not-found"):
        raise ValueError("failed to read " + unit)
    return v

def drained(name):
    row=native(name)
    cg=Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs"
    if row["ActiveState"] not in ("inactive","failed") or row["SubState"] not in ("dead","failed") or row["Job"] or any(row.get(k,"0") not in ("0","") for k in ("MainPID","ControlPID")) or (cg.exists() and cg.read_bytes().strip()):
        raise ValueError("still occupied " + name)
    return row

def run(mode):
    if os.geteuid() or not sys.flags.isolated or not __debug__ or mode not in ("inspect","retire"):
        raise ValueError("invalid original timer retirement")
    load_package(CAD,SEAL)
    sys.path.insert(0,str(CAD))
    import guard_stops as stops
    from evidence import checked, content, durable
    refs=stops.stops()
    stops.assert_drained(refs)
    fleet=checked(stops.PREVIOUS)
    expected={}
    for row in fleet["actual_executing_replays"]:
        e=str(row["epoch"])
        if e not in refs: continue
        own=checked(row["guard_protection"])
        if own["producer_invocation_id"] != checked(refs[e])["terminal_producer_invocation_id"]:
            raise ValueError("wrong original generation")
        expected[e]={k:own[k] for k in ("producer_unit","producer_invocation_id","guard_unit","timer_unit","timer_invocation_id")}
    if set(expected)!=set(refs):raise ValueError("missing original booking")
    if Q.exists():
        value=content(Q)
        if value["expected"]!=expected or value["reports"]!=refs:raise ValueError("retirement binding differs")
        for v in expected.values():
            drained(v["timer_unit"]);drained(v["guard_unit"])
        return value
    intent=D/"ORIGINAL_GUARD_TIMERS_RETIRE_INTENT.json"
    previous=content(intent) if intent.exists() else None
    if previous and (previous["reports"]!=refs or previous["expected"]!=expected):
        raise ValueError("foreign original guard retirement transaction")
    before=previous["before"] if previous else {}
    pending=[]
    for e,v in expected.items():
        t=native(v["timer_unit"])
        if previous and t["ActiveState"]=="inactive":
            drained(v["timer_unit"])
            continue
        if (t["Id"]!=v["timer_unit"] or t["InvocationID"]!=v["timer_invocation_id"] or t["ActiveState"]!="active" or t["Triggers"]!=v["guard_unit"] or t["Job"]):
            raise ValueError("original timer mismatch "+e)
        before[e]=t
        pending.append(v["timer_unit"])
    if mode=="inspect":return dict(expected=expected,before=before)
    D.mkdir(mode=0o700,exist_ok=True)
    if not previous:
        durable(intent,dict(expected=expected,reports=refs,before=before))
    if pending:
        subprocess.run(["/usr/bin/systemctl","stop",*pending],check=True,timeout=20)
    stops.assert_drained(refs)
    deadline=time.monotonic()+15
    while True:
        try:
            after={e:[drained(v["timer_unit"]),drained(v["guard_unit"])] for e,v in expected.items()}
            break
        except ValueError:
            if time.monotonic()>deadline:raise
            time.sleep(.2)
    value=dict(schema="horizon-original-data-stop-guard-timer-retirement-v1",reports=refs,expected=expected,
               before=before,after=after,recorded_unix_seconds=int(time.time()))
    D.mkdir(mode=0o700,exist_ok=True)
    durable(Q,value)
    return value

if __name__=="__main__":
    print(json.dumps(run(sys.argv[1]),sort_keys=True))
