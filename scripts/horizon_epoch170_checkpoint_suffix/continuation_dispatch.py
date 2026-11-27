"""Dispatch the read-only comparison, protected actor and enrollment-dependent release."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


q = load("continuation_price")
operator = load("bounded_successor")
persist = load("closed_successor").persist


def record(path, doc):
    persist(path,(json.dumps(doc, indent=2)+"\n").encode())
    return q.read(path)[1]


def closed():
    i,_ = q.scope()
    dest = Path(i["closed_comparison"])
    if dest.exists(): return q.compare_predecessor()
    q.predecessor_exit()
    handoff = q.bound(i["closed_terminal_handoff"])
    native = Path(handoff["closed_argv"][0])
    seal = q.bound(handoff["closure_seal"])
    expected = [m for m in seal["members"] if m["name"] == "bounded-checkpoints"]
    q.need(len(expected)==1 and native == Path(seal["destination"])/expected[0]["name"]
           and hashlib.sha256(native.read_bytes()).hexdigest()==expected[0]["sha256"],"changed native checker")
    fit = q.price("read")
    q.need(fit["fits"] and 0 <= time.time()-fit["observed"] < 30,
           "readback capacity (HOME,RAM): "+str((fit["home_margin"],fit["ram_margin"])))
    fit_ref = record(q.DEP/("READ_FIT_"+str(time.time_ns())+".json"),fit)
    q.inactive(q.READ_UNIT)
    start = int(time.time())
    props = ["CPUQuota=100%","MemoryMax=512M","MemorySwapMax=0","TasksMax=16","Nice=8","RuntimeMaxSec=2h",
             "User=root","Group=root","NoNewPrivileges=yes","PrivateNetwork=yes","ProtectSystem=strict",
             "ProtectHome=read-only","PrivateTmp=yes","UMask=0077"]
    args = ["/usr/bin/systemd-run","--quiet","--wait","--pipe","--collect","--service-type=exec","--unit="+q.READ_UNIT]
    for prop in props: args.extend(["--property",prop])
    result = subprocess.run(args+["--",*handoff["closed_argv"]],capture_output=True,timeout=7250)
    q.need(result.returncode == 0, "native comparison failed: "+result.stderr.decode(errors="replace")[-1700:])
    data = json.loads(result.stdout)
    e = data["evidence"]
    q.need(data["release"]==i["old_release"] and data["actor"]==i["old_actor"] and
           [r["slot"] for r in data["checkpoints"]]==[73726716,73746882] and
           e["comparison"]=="closed" and e["pid1_exit"]["native"]["InvocationID"]==q.ORIG
           and len(e["closed_segment"]["sha256"])==64 and not data["canonical_publication_authorized"],
           "different native close result")
    logs = [json.loads(l) for l in q.cmd("/usr/bin/journalctl","-q","--no-pager","-o","json","--since","@"+str(start),
            "_PID=1","_UID=0","UNIT="+q.READ_UNIT,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448").splitlines()]
    q.need(len(logs)==1 and len(logs[0]["INVOCATION_ID"])==32,"no unique successful native reader invocation")
    comparison = record(dest,data)
    record(q.DEP/"CLOSED_READ_ACCEPTANCE.json",dict(comparison=comparison,reader_fit=fit_ref,
           reader_invocation=logs[0]["INVOCATION_ID"],ended=int(time.time()),publication_authorized=False))
    return q.compare_predecessor()


def dispatch(stage):
    i, ir = q.scope()
    q.need(operator.q.UNIT == q.UNIT and operator.D == q.DEP, "operator is outside its sealed deployment")
    q.need(Path(__file__).resolve().parent == q.DEP/"operator","wrong dispatch executable directory")
    if stage == "check":
        operator.static()
        return {"interface":ir,"wait_for":str(q.DEP/"predecessor-exit/PID1_EXIT.json")}
    closed()
    if stage == "close": return q.compare_predecessor()
    if (q.DEP/"SUCCESSOR_RELEASE.json").exists():
        v,ref=q.read(q.DEP/"SUCCESSOR_RELEASE.json")
        q.need(v["interface"]==ir and q.bound(v["actor"])["unit"]==q.UNIT,"unknown successor release")
        return ref
    if not (q.DEP/"SUCCESSOR_ACTOR.json").exists():
        q.need(stage=="advance","actor is not held")
        operator.start()
    operator.same_actor()
    if not (q.DEP/"ACTUAL_GUARD_PLAN.json").exists():
        q.need(stage=="advance","no actual guard")
        operator.arm()
    if not (q.DEP/"WRITER_ENROLLMENT.json").exists(): return {"held_actor":q.read(q.DEP/"SUCCESSOR_ACTOR.json")[1],
            "held_guard_plan":q.read(q.DEP/"ACTUAL_GUARD_PLAN.json")[1],"awaiting_exact_writer_enrollment":True}
    return operator.release()


def main():
    q.need(len(sys.argv)==2 and sys.argv[1] in ("check","close","advance","release"),"select an operational phase")
    stage=sys.argv[1]
    fd=os.open(q.DEP/"bounded-operator.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX)
    try:
        print(json.dumps(dispatch(stage)),flush=True)
    except Exception as error:
        record(q.DEP/("DISPATCH_REFUSED_"+str(time.time_ns())+".json"),
               dict(stage=stage,error=str(error),observed=int(time.time()),archive_publication_authorized=False))
        raise
    finally: os.close(fd)


if __name__=="__main__": main()
