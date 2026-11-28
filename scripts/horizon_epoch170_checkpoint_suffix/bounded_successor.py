"""Control the single private 73,726,716 to 73,746,882 epoch 170 segment."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+".py"))
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


NEXT_DEPLOYMENT=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/operator")
RETRY_OPERATORS = {NEXT_DEPLOYMENT.parent/"attempt-2"/name for name in ("operator-v1", "operator-v2", "operator-v3")}
FOLLOWING_DEPLOYMENT = NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73766969-20261127-v1/operator-v1"
ENROLLING_FOLLOWING = FOLLOWING_DEPLOYMENT.with_name("operator-v2")
FOLLOWING_READER = FOLLOWING_DEPLOYMENT.with_name("closed-reader-v1")
RECONCILED_FOLLOWING = FOLLOWING_DEPLOYMENT.with_name("operator-v3")
SPLIT_FOLLOWING = FOLLOWING_DEPLOYMENT.with_name("operator-v4")
CHAIN_FOLLOWING = FOLLOWING_DEPLOYMENT.with_name("operator-v5")
ENROLLING_OPERATORS = {ENROLLING_FOLLOWING, RECONCILED_FOLLOWING, SPLIT_FOLLOWING, CHAIN_FOLLOWING}
FOLLOWING_READERS = {FOLLOWING_READER, FOLLOWING_READER.with_name("closed-reader-v2"), FOLLOWING_READER.with_name("closed-reader-v3"), FOLLOWING_READER.with_name("closed-reader-v4")}
CONTINUATIONS = ENROLLING_OPERATORS | {FOLLOWING_DEPLOYMENT, NEXT_DEPLOYMENT, NEXT_DEPLOYMENT.with_name("operator-with143-v1"), NEXT_DEPLOYMENT.with_name("operator-with143-v2")}
GAP_DEPLOYMENT = NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73760367-20261128-v1/operator-v1"
RAM_GAP_DEPLOYMENT = NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73760367-ram-20261128-v1/operator-v1"
SECOND_RAM_GAP = Path(__file__).resolve().parent == NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73760367-ram-20261128-v2/operator-v1"
THIRD_RAM_GAP = Path(__file__).resolve().parent == NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73760367-ram-20261128-v3/operator-v1"
RAM_GAP = THIRD_RAM_GAP or SECOND_RAM_GAP or Path(__file__).resolve().parent == RAM_GAP_DEPLOYMENT
AFTER_RAM = Path(__file__).resolve().parent == NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73766969-gap-20261128-v1/operator-v1"
HOURLY_RAM = Path(__file__).resolve().parent == NEXT_DEPLOYMENT.parent.parent / "epoch170-from-73766969-ram-20261128-v1/operator-v1"
AFTER_RAM = AFTER_RAM or HOURLY_RAM
GAP = RAM_GAP or Path(__file__).resolve().parent == GAP_DEPLOYMENT
ENTRY_FIELD = "independent_checkpoint" if GAP else "closed_comparison"
if AFTER_RAM:
    q = load("after_ram170_issuer")
    if HOURLY_RAM:
        workspace = load("ram170_workspace")
elif RAM_GAP:
    if THIRD_RAM_GAP:
        q = load("ram170_third_price")
    elif SECOND_RAM_GAP:
        q = load("ram170_second_price")
    else:
        q = load("ram170_price")
    workspace = load("ram170_workspace")
elif GAP:
    q = load("gap170_price")
elif Path(__file__).resolve().parent in CONTINUATIONS | RETRY_OPERATORS | FOLLOWING_READERS:
    q = load("continuation_price")
else:
    q = load("successor_price")
persist=load("closed_successor").persist
D=q.ATTEMPT
UNIT=q.UNIT
ALIAS=getattr(q,"ALIAS","/run/horizon-170-from-73726716-v1")
GUARD=UNIT.replace("-qualify-","-guard-")
TIMER=GUARD.replace(".service",".timer")
need=q.need
G=1<<30


def save(name,v):
    p=D/name
    persist(p,(json.dumps(v,indent=2)+"\n").encode())
    return q.read(p)[1]


def save_fit(name, document):
    # Keep a finished fit if the original one-shot stopped before recording its next step.
    if AFTER_RAM and (D/name).exists():
        name = Path(name).stem + "_" + str(time.time_ns()) + ".json"
    return save(name, document)


def current(name):
    return q.read(D/name)


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def static():
    i,ir=q.scope()
    profile=i["profile"]
    ns=q.bound(i["namespace"])
    layout=q.bound(i["layout"])
    package=Path(profile["sealed_package"]["path"]).parent
    seal=q.bound(profile["sealed_package"])
    for member in seal["members"]:
        src=package/member["name"]
        need(src.resolve()==src and src.stat().st_size==member["bytes"] and digest(src)==member["sha256"],
             "changed deployment "+str(src))
    spec=Path(layout["service"]["path"])
    need(ns["unit"]==layout["service"] and ns["layout"]==i["layout"] and digest(spec)==layout["service"]["sha256"]
         and ns["seal"]==profile["sealed_package"] and layout["run"]==i["run"],"namespace differs")
    # Verify complete preflight inode/time bindings before deciding to start.
    bindings=ns["report"]["readonly_bindings"]
    for line in spec.read_text().splitlines():
        if line.startswith("BindReadOnlyPaths="):
            src,dst=line.split("=",1)[1].split(":")
            m=Path(src).stat()
            ref=bindings[dst]
            need([m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns][:len(ref)]==ref,"changed input "+src)
    return i,ir


def compare():
    if hasattr(q, "compare_predecessor"):
        return q.compare_predecessor()
    v,ref=q.read(q.scope()[0]["closed_comparison"])
    need(v["release"]==q.scope()[0]["old_release"] and v["pid1_exit"]["native"]["InvocationID"]==q.ORIG
         and v["pid1_exit"]["native"]["Result"]=="success" and v["checkpoints"][-1]["slot"]==73726716
         and len(v["closed_segment"]["sha256"])==64 and v["mode"]=="closed" and not v["publication_authorized"],
         "missing closed predecessor")
    return ref


def checked_price(phase):
    v=q.price(phase)
    need(v["fits"],f'{phase} fit failed: disk {v["home_margin"]}, RAM {v["ram_margin"]}, cap {v["guard_cap"]}')
    need(time.time()-v["observed"]<30,"expired price")
    return v


def actor(held=True):
    i,ir=q.scope()
    s=q.state(UNIT)
    iid=s["InvocationID"];pid=int(s["MainPID"]);proc=Path("/proc")/str(pid)
    memory = q.PRODUCER_MEMORY if RAM_GAP or HOURLY_RAM else 48*G
    need(re.fullmatch("[0-9a-f]{32}",iid) and iid!="0"*32 and s["ActiveState"]=="active"
         and not s["Job"] and s["ControlPID"]=="0" and s["MemoryMax"]==str(memory) and s["MemorySwapMax"]=="0"
         and s["CPUQuotaPerSecUSec"]=="6s" and s["ControlGroup"]=="/system.slice/"+UNIT,"foreign producer")
    cg=Path("/sys/fs/cgroup"+s["ControlGroup"])
    members={int(p) for p in (cg/"cgroup.procs").read_text().split()}
    need((members=={pid} if held else pid in members) and (cg/"cpu.max").read_text().split()==["600000","100000"]
         and int((cg/"memory.max").read_text())==memory and (cg/"memory.swap.max").read_text().strip()=="0",
         "actual scheduling limits or members changed")
    target=Path(i["profile"]["sealed_package"]["path"]).with_name("gate") if held else Path(i["profile"]["node"]["path"])
    need((proc/"exe").samefile(target) and (proc/"cgroup").read_text().strip()=="0::"+s["ControlGroup"],
         "producer is not the expected gate/node")
    ticks=int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])
    ns=q.bound(i["namespace"])["report"]
    root=proc/"root"
    for dst,identity in ns["readonly_bindings"].items():
        f=root/dst.lstrip("/")
        m=f.stat()
        need([m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns][:len(identity)]==identity
             and os.statvfs(f).f_flag & os.ST_RDONLY, "foreign or writable projection "+dst)
    run=Path(i["run"])
    if RAM_GAP or HOURLY_RAM:
        workspace.mount(pid, run / "scratch")
    dev=run.stat().st_dev
    major_minor=f"{os.major(dev)}:{os.minor(dev)}"
    mtab=[l.split(" - ",1)[0].split() for l in (proc/"mountinfo").read_text().splitlines()]
    w=set()
    for m in mtab:
        if m[2]!=major_minor or "rw" not in m[5].split(","):
            continue
        visible=root/m[4].lstrip("/")
        try:
            writable=visible.stat().st_dev==dev and not os.statvfs(visible).f_flag & os.ST_RDONLY
        except FileNotFoundError:
            continue
        if writable:
            w.add(m[4])
    need(w=={str(run)}, "unexpected visible writable HOME mounts "+repr(w))
    need(not any(t.startswith(("shared:","master:")) for v in mtab
                 if v[4]=="/" or v[4].startswith(("/home/sol","/var/lib/jetstreamer",ALIAS)) for t in v[6:]),
         "producer mounts have shared propagation")
    for fd in [1,2]:
        need((proc/"fd"/str(fd)).samefile(i["log"]), "unbound output stream")
    need(q.state(UNIT)==s, "producer changed during validation")
    return dict(schema="horizon-epoch170-bounded-successor-actor-v1",unit=UNIT,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),producer_invocation_id=iid,
                producer_pid=pid,start_ticks=ticks,interface=ir)


def start():
    i,ir=static()
    closed=compare()
    if AFTER_RAM:
        q.predecessor_drained()
        if (D/"SUCCESSOR_START_INTENT.json").exists():
            return q.recover_start(actor, save, ir, closed)
    else:
        old_guard=q.bound(i["handoff"])["live_guard"]
        old_timer=q.BRIDGE.replace("-qualify-","-guard-").replace(".service",".timer")
        st=q.state(old_timer,"Id,ActiveState,InvocationID,Job")
        if GAP:
            q.retained_guard(st, old_guard)
        elif st["ActiveState"]=="active":
            loan=q.B140/"CPU_LOAN_RETURN.json"
            need(loan.exists() and q.read(loan)[0]["producer_and_guard_drained"]
                 and st["InvocationID"]==old_guard["timer_invocation_id"],"old guard still protects active CPU loan")
            q.inactive(q.BRIDGE)
            subprocess.run(["/usr/bin/systemctl","stop",old_timer],check=True)
        q.inactive(q.BRIDGE)
        if not GAP:
            q.inactive(old_timer.replace(".timer",".service"))
    q.inactive(UNIT)
    q.inactive(GUARD)
    need(q.state(TIMER,"Id,ActiveState,Job")["ActiveState"]=="inactive","successor guard already active")
    run=Path(i["run"])
    need(not os.path.lexists(i["barrier"]) and not (D/"SUCCESSOR_ACTOR.json").exists()
         and not any((run/n).exists() and any((run/n).iterdir()) for n in ("scratch","private","tmp"))
         and (not Path(i["log"]).exists() or Path(i["log"]).stat().st_size==0),"occupied successor")
    directory=Path(i["guard_receipts"])
    directory.mkdir(0o700,exist_ok=True)
    need(directory.stat().st_uid==0 and not (directory/"stop-intent.json").exists(),"occupied guard scope")
    if D == q.DEP:
        need(not any(directory.iterdir()), "foreign first-attempt guard samples")
        if getattr(q, "RETRY", False):
            previous=q.bound(i["unreleased_failed_attempt"])["terminal"]
            prior=q.inactive(UNIT)
            if prior["ActiveState"]=="failed":
                need(prior["InvocationID"]==previous["InvocationID"], "different terminal producer")
                subprocess.run(["/usr/bin/systemctl","reset-failed",UNIT],check=True)
                q.inactive(UNIT)
    else:
        failed=q.bound(i["failed_predecessor"])
        previous=q.bound(failed["actor"])
        for item in directory.iterdir():
            if re.fullmatch(r"sample-[a-f0-9]{32}\.json", item.name):
                sample,_=q.read(item)
                need(sample["plan_sha256"]==failed["guard_plan"]["sha256"]
                     and sample["producer_invocation_id"]==previous["producer_invocation_id"],
                     "unknown prior protective sample "+str(item))
            else:
                need(item.name.endswith(".lock") and item.is_file() and item.stat().st_uid==0,
                     "unknown guard namespace entry "+str(item))
        prior=q.state(UNIT)
        if prior["ActiveState"]=="failed":
            need(prior["InvocationID"]==previous["producer_invocation_id"] and prior["MainPID"]=="0",
                 "foreign failed unit")
            subprocess.run(["/usr/bin/systemctl","reset-failed",UNIT],check=True)
        guard_state=q.state(GUARD)
        if guard_state["ActiveState"]=="failed":
            need(guard_state["MainPID"]=="0" and not guard_state["Job"], "old guard has an active owner")
            subprocess.run(["/usr/bin/systemctl","reset-failed",GUARD],check=True)
    fit=checked_price("start")
    if RAM_GAP:
        q.transfer_guard(save)
        fit=checked_price("start")
    fref=save_fit("SUCCESSOR_START_FIT.json",fit)
    intent_ref=save("SUCCESSOR_START_INTENT.json",dict({ENTRY_FIELD: closed},interface=ir,price=fref,
        producer_unit=UNIT,guard_unit=GUARD,guard_floor=fit["guard_floor"],guard_cap=fit["guard_cap"],
        resource_credit_bytes=0,archive_publication_authorized=False))
    unit=Path(q.bound(i["layout"])["service"]["path"])
    props=[]
    for line in unit.read_text().splitlines():
        if "=" not in line:
            continue
        key,value=line.split("=",1)
        if key in ("ExecStart","Description","Type"):
            continue
        if getattr(q, "RETRY", False) and key == "StandardOutput":
            original = q.bound(i["previous_interface"])
            need(value == "append:"+original["log"], "changed original output stream")
            line = "StandardOutput=append:"+i["log"]
        props+=["--property",line]
    props+=["--property","InaccessiblePaths=-/run/jetstreamer-ready-bounds-20261121-v1"]
    if AFTER_RAM:
        props.extend(["--property", "Environment=HORIZON_170_START_INTENT_SHA256=" + intent_ref["sha256"]])
    need(time.time()-fit["observed"]<60, "priced start expired")
    subprocess.run(["/usr/bin/systemd-run","--quiet","--service-type=exec","--unit="+UNIT,*props,"--",
                    "/usr/bin/env",ALIAS+"/gate"],check=True)
    for _ in range(100):
        try:
            a=actor()
            break
        except (FileNotFoundError,ValueError):
            time.sleep(.05)
    else:
        a=actor()
    return save("SUCCESSOR_ACTOR.json",a)


def same_actor():
    a,ar=current("SUCCESSOR_ACTOR.json")
    need(actor()==a,"held actor changed")
    return a,ar


def funded_guard(fit, floor, cap):
    low, high = fit["terminal_tree_bounds"]
    if floor < fit["guard_floor"] or cap < high:
        return False
    remaining = max(0, cap - low)
    if "assembly168" not in fit:
        return fit["available_home"] >= floor + remaining
    # The fresh joint fit includes outstanding assembler writes. Keep that
    # runway separate from the constant free-space threshold enforced by 170.
    growth = fit.get("candidate_170_growth_bytes", fit["joint"]["candidate_growth"])
    required = fit["required_home"] + (floor - fit["guard_floor"]) + max(0, remaining - growth)
    return fit["available_home"] >= required + fit.get("shared_drawdown_allowance", 0)


def arm():
    i,_=static()
    a,ar=same_actor()
    intent,_=current("SUCCESSOR_START_INTENT.json")
    fit=checked_price("held")
    if SECOND_RAM_GAP or THIRD_RAM_GAP or HOURLY_RAM:
        # The locked held fit already measures outstanding peer growth. The
        # release step rechecks this floor against its new complete-fleet fit.
        floor=fit["guard_floor"]
    else:
        floor=max(intent["guard_floor"],fit["guard_floor"])
        if RAM_GAP:
            remaining = max(0, fit["home_margin"] - (floor-fit["guard_floor"]))
            floor += min(4*G, remaining//2)
        else:
            floor += min(G, max(0,fit["home_margin"])//2)
    cap=intent["guard_cap"]
    need(funded_guard(fit, floor, cap),
         "held floor/cap cannot cover remaining growth")
    held=save_fit("SUCCESSOR_HELD_FIT.json",fit)
    plan=dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=UNIT,invocation_id=a["producer_invocation_id"],
              filesystem="/home/sol",worker_root=str(q.TREE),receipt_directory=i["guard_receipts"],
              maximum_worker_vmas=3500000,minimum_free_bytes=floor,maximum_root_physical_bytes=cap)
    pr=save("ACTUAL_GUARD_PLAN.json",plan)
    start_guard(i, pr)
    return dict(actor=ar,plan=pr,held_price=held)


def start_guard(i, pr):
    exe=Path(i["guard_seal"]["path"]).with_name("guard");argv=[str(exe),pr["path"],"--plan-sha256",pr["sha256"],"--self-sha256",i["guard_sha"]]
    validate=json.loads(q.cmd(*argv,"--validate-plan-only"))
    need(validate["validated"] and validate["resource_samples_taken"]==0 and digest(exe)==i["guard_sha"],"invalid guard")
    args=["/usr/bin/systemd-run","--quiet","--unit="+GUARD,"--on-active=1s","--on-unit-inactive=5s",
          "--timer-property=AccuracySec=1s","--service-type=oneshot"]
    for prop in ["User=root","Group=root","UMask=0077","MemoryMax=1G","MemorySwapMax=0","CPUQuota=100%",
                 "TasksMax=256","TimeoutStartSec=120","TimeoutStopSec=15","PrivateNetwork=yes","ProtectSystem=strict",
                 "ProtectHome=read-only","PrivateTmp=yes","NoNewPrivileges=yes",
                 "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
                 "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL","ReadWritePaths="+i["guard_receipts"]]:
        args.extend(["--property",prop])
    same_actor()
    subprocess.run([*args,"--",*argv],check=True)


def guard():
    a,_=same_actor()
    plan,pref=current("ACTUAL_GUARD_PLAN.json")
    samples=Path(plan["receipt_directory"])
    need(not (samples/"stop-intent.json").exists(),"guard stop")
    candidates=list(samples.glob("sample-*.json"))
    need(candidates,"guard has not sampled")
    s,sref=q.read(max(candidates,key=lambda f:f.stat().st_mtime_ns))
    ts=q.state(TIMER,"Id,ActiveState,InvocationID,Job,Triggers")
    need(ts["ActiveState"]=="active" and ts["Triggers"]==GUARD and not ts["Job"] and len(ts["InvocationID"])==32
         and s["plan_sha256"]==pref["sha256"] and s["producer_invocation_id"]==a["producer_invocation_id"]
         and s["producer"]["pid"]==a["producer_pid"] and s["producer_stop_enabled"] and s["trip_reason"] is None
         and s["workers"]==[] and s["worker_observation_error"] is s["root_physical_observation_error"] is None
         and not s["root_physical_observation"]["exceeds_budget"] and s["available_bytes"]>=plan["minimum_free_bytes"]
         and time.time()-s["recorded_unix_seconds"]<=75,"invalid protective held guard")
    return sref,ts["InvocationID"],plan,pref


def release():
    i,ir=static()
    closed=compare()
    a,ar=same_actor()
    e,er=current("WRITER_ENROLLMENT.json")
    need(e["enrolled"] and not e["publication_authorized"] and e["actor"]==ar and e[ENTRY_FIELD]==closed
         and e["interface"]==ir,"different writer enrollment")
    writer=q.bound(e["writer_active"])["new"]
    ws=q.state(writer["unit"])
    need(ws["ActiveState"]=="active" and ws["InvocationID"]==writer["invocation_id"] and int(ws["MainPID"])==writer["pid"]
         and int((Path("/proc")/str(writer["pid"])/"stat").read_text().rsplit(") ",1)[1].split()[19])==writer["start_ticks"],
         "writer replaced")
    sample,ti,plan,pr=guard()
    fit=checked_price("held")
    need(funded_guard(fit, plan["minimum_free_bytes"], plan["maximum_root_physical_bytes"]),
         "joint postguard HOME coverage failed")
    fp=save_fit("SUCCESSOR_POST_GUARD_FIT.json",fit)
    admission=save_fit("SUCCESSOR_AUTHORIZED_RELEASE.json",dict({ENTRY_FIELD: closed},actor=ar,interface=ir,
                   writer_enrollment=er,guard_plan=pr,post_guard_capacity=fp,first_guard_sample=sample,
                   producer_invocation_id=a["producer_invocation_id"],archive_publication_authorized=False))
    sr=save("SUCCESSOR_RELEASE.json",dict(schema="horizon-epoch170-bounded-successor-release-v1",actor=ar,
               interface=ir,producer_invocation_id=a["producer_invocation_id"],guard_plan=pr,first_guard_sample=sample,
               guard_timer_invocation_id=ti,admission=admission,resource_credit_bytes=0,archive_publication_authorized=False,
               writer_enrollment=er,post_guard_capacity=fp,**{ENTRY_FIELD:closed}))
    current_guard,again,_,_=guard()
    need(again==ti and q.state(writer["unit"])==ws and time.time()-fit["observed"]<=90,"release bindings expired")
    publish_permit(Path(i["barrier"]), a["producer_invocation_id"])
    return dict(released=sr,guard_at_commit=current_guard)


def publish_permit(path, invocation):
    # The unprivileged gate must see a complete, readable invocation at first visibility.
    tmp=path.parent/(".permit-"+invocation+("-"+str(time.time_ns()) if AFTER_RAM else ""))
    fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o400)
    try:
        data = invocation.encode()
        need(os.write(fd,data) == len(data), "incomplete permit write")
        os.fchmod(fd,0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renameat2(-100,os.fsencode(tmp),-100,os.fsencode(path),1)!=0:
        raise OSError(ctypes.get_errno(),"exclusive permit publication")
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


if __name__=="__main__":
    stages={"start":start,"arm":arm,"release":release}
    need(len(sys.argv)==2 and sys.argv[1] in stages,"select start, arm, or release")
    lock=os.open(D/"bounded-operator.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    print(json.dumps(stages[sys.argv[1]](),sort_keys=True),flush=True)
