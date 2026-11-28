"""Generate the gate bindings from real producer, guard, timer and postguard receipts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import time

HERE=Path(__file__).resolve().parent
h=runpy.run_path(str(HERE/"hourly.py"))
a=runpy.run_path(str(HERE/"actor.py"))
g=runpy.run_path(str(HERE/"hourly_gate.py"))
C=h["CONTROL"]
need=h["need"]
UNIT=h["UNIT"]
WATCH="horizon-169-hourly-terminal-20261123-v1.service"


def ref(path):
    return dict(path=str(path),sha256=h["sha"](path))


def locked(path):
    r=ref(path)
    return a["pinned"](r),r


def owner():
    p=a["props"](UNIT,["Id","ActiveState","SubState","InvocationID","MainPID","NRestarts","Job","OnSuccess","OnFailure"])
    need(p["Id"]==UNIT and p["ActiveState"]=="active" and p["SubState"]=="running" and p["NRestarts"]=="0"
         and not p["Job"] and int(p["MainPID"])>1 and p["OnSuccess"].split()==[WATCH] and p["OnFailure"].split()==[WATCH],
         "hourly producer is not held with its event watcher")
    pid=int(p["MainPID"])
    proc=Path("/proc")/str(pid)
    need((proc/"cmdline").read_bytes().rstrip(b"\0").split(b"\0")==
         [b"/usr/bin/python3",b"-IB",b"/run/horizon-169-hourly/hourly_gate.py"] and
         os.path.samefile(proc/"exe","/usr/bin/python3") and
         (proc/"cgroup").read_text().strip()=="0::/system.slice/"+UNIT,"payload is not in its prestart barrier")
    return p,int((proc/"stat").read_text().rsplit(")",1)[1].split()[19])


def verified_watcher():
    s=a["props"](WATCH,["Id","LoadState","ActiveState","Job","FragmentPath","ExecStart","CPUQuotaPerSecUSec","MemoryMax","MemorySwapMax"])
    p=Path(s["FragmentPath"])
    need(s["Id"]==WATCH and s["LoadState"]=="loaded" and s["ActiveState"]=="inactive" and not s["Job"] and
         s["CPUQuotaPerSecUSec"]=="1s" and int(s["MemoryMax"])==1<<30 and s["MemorySwapMax"]=="0" and
         p in (Path("/run/systemd/system")/WATCH,Path("/etc/systemd/system")/WATCH) and p.resolve(strict=True)==p and
         p.stat().st_uid==0 and not p.stat().st_mode&0o022 and
         "/usr/bin/python3 -IB "+str(C/"sealed/watch.py")+" --terminal-event" in s["ExecStart"] and
         h["sha"](p)==h["sha"](C/"sealed"/WATCH), "event watcher service differs from sealed source")
    return dict(properties=s,fragment=ref(p),watch=ref(C/"sealed/watch.py"))


def basis():
    pre,pre_ref=locked(C/"PRESTART.json")
    need(pre["current_native_fit"] and pre["grants"]==0 and pre["native"]["fits"] and
         pre["native"]["replay_launch_authorized"] is False and pre["native"]["closed_focused169"]["producer_invocation_id"]==
         "0dfa0d36fbc246c28443a1c90a82c9cb" and pre["native"]["fleet"]==pre["fleet"] and
         pre["screen"]["future_staging"]==0 and pre["screen"]["private_workspace"]==a["WORKSPACE"] and
         pre["screen"]["margin"]>=0 and pre["native"]["candidate136"]["occupied"] is False,
         "prestart did not capture the paid restored-source fleet")
    source=pre["sources"]["169"]
    report=h["bound"](dict(path=source["receipt"],sha256=source["sha256"]))
    bank,row=h["restore_receipt"](h["pin"](h["RESTORE"],h["RESTORE_SHA"])["plans"][1],report)
    need(row==source["file"],"source receipt changed after staging")
    st=h["same_file"](bank,row)
    need(pre["snapshot_identity"]==[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns],
         "Bank changed since the prestart digest")
    return pre,pre_ref,st


def new_plan():
    pre,_,st=basis()
    producer,_=owner()
    cap=st.st_blocks*512+pre["screen"]["worker_growth"]
    return h["guard_plan"](producer["InvocationID"],pre["screen"]["protected_HOME"]+a["FIXED"],cap)


def guard_args():
    p=C/"guard-plan/guard-plan.json"
    plan,reference=locked(p)
    need(plan==new_plan(),"sealed guard plan differs from real actor")
    return h["guard_argv"](p,reference["sha256"])


def first(sample_path):
    pre,pre_ref,st=basis()
    producer,ticks=owner()
    plan,plan_ref=locked(C/"guard-plan/guard-plan.json")
    sample,sample_ref=locked(sample_path)
    need(plan==new_plan() and sample_path==Path(plan["receipt_directory"])/("sample-"+sample["guard_invocation_id"]+".json")
         and sample["plan"]==plan_ref["path"],"different held guard plan")
    guard=a["props"](h["GUARD_UNIT"]+".service",["Id","InvocationID","Result","ExecMainStatus","Job","TriggeredBy"])
    timer=a["props"](h["GUARD_UNIT"]+".timer",["Id","ActiveState","Job","Triggers","InvocationID"])
    h["first_guard"](sample,plan,plan_ref["sha256"],producer,timer,guard)
    watcher=verified_watcher()
    return dict(schema="epoch169-hourly-bound-first-guard-intent-v1",unit=UNIT,pid=int(producer["MainPID"]),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),producer_invocation_id=producer["InvocationID"],
                previous_producer_iid=pre["native"]["closed_focused169"]["producer_invocation_id"],
                previous_terminal=pre["native"]["closed_focused169"]["terminal"],timer_iid=timer["InvocationID"],
                start_ticks=ticks,sealed_node=pre["verified_release"]["node"],guard_plan=plan_ref,first_guard=sample_ref,
                timer=timer,guard=guard,watcher=watcher,original_prestart=pre_ref,prestart_physical_bytes=st.st_blocks*512,
                actor_memory_bytes=68<<30,guard_memory_bytes=1<<30,actor_cpu_micros=3_000_000,guard_cpu_micros=1_000_000,
                fixed_control_allowance=a["FIXED"],charged_worker_growth=a["WORKSPACE"]-a["FIXED"],canonical_publication_authorized=False)


def grant():
    intent,iref=locked(C/"START_INTENT.json")
    post,pref=locked(C/"POST_GUARD_CAPACITY.json")
    pre,pre_ref,st=basis()
    provider=pre["native"].get("hourly169_provider")
    need(post["fits"] and post["complete_cpu"]==a["CPU"] and post["complete_memory"]==a["RAM"] and
         post["private_actor"]["intent"]==iref and post["private_actor"]["held"] and
         post["private_actor"]["producer_iid"]==intent["producer_invocation_id"] and pre_ref==intent["original_prestart"]
         and post["native"]["fleet"]==pre["fleet"]
         and post["native"].get("hourly169_provider")==provider
         and (provider is None or post["native"]["phase145"]==pre["native"]["phase145"])
         and 0<=time.time()-post["native"]["recorded_unix_seconds"]<=90,
         "no fresh, held, independently priced actor")
    bound=a["before"](h["bound"](pre["fleet"]))
    need(bound==post["private_actor"] and verified_watcher()==intent["watcher"],"native actor or watcher changed")
    p,t=owner(); log=h["RUN"]/"producer.log";lm=log.lstat()
    need(log.resolve(strict=True)==log and lm.st_nlink==1 and lm.st_size==0,"foreign pre-payload log")
    result=dict(schema="epoch169-hourly-private-postguard-release-v1",unit=UNIT,invocation_id=p["InvocationID"],
                pid=int(p["MainPID"]),start_ticks=t,boot_id=intent["boot_id"],issued_unix_seconds=int(time.time()),
                first_guard_sha256=intent["first_guard"]["sha256"],native_post_guard_price_sha256=pref["sha256"],
                registered_watcher_sha256=hashlib.sha256(json.dumps(intent["watcher"],sort_keys=True).encode()).hexdigest(),
                verified_source_receipt_sha256=pre["sources"]["169"]["sha256"],guard_plan_sha256=intent["guard_plan"]["sha256"],
                snapshot_sha256=pre["sources"]["169"]["file"]["sha256"],snapshot_identity=pre["snapshot_identity"],
                producer_cpu_micros=3_000_000,guard_cpu_micros=1_000_000,memory_max=68<<30,guard_memory_max=1<<30,
                log_device=lm.st_dev,log_inode=lm.st_ino,canonical_publication_authorized=False)
    g["verify_grant"](result,result["invocation_id"],result["pid"],t,result["boot_id"],time.time())
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(__doc__)
    sub=parser.add_subparsers(required=True,dest="stage")
    sub.add_parser("plan"); sub.add_parser("grant");sub.add_parser("guard-argv")
    first_args=sub.add_parser("first");first_args.add_argument("sample",type=Path)
    args=parser.parse_args()
    if args.stage=="first":
        result=first(args.sample)
    else:
        result={"plan":new_plan,"guard-argv":guard_args,"grant":grant}[args.stage]()
    print(json.dumps(result,sort_keys=True,indent=2))
