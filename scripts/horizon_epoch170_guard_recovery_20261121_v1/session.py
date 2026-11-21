#!/usr/bin/python3 -IB
"""Start the original 170 normal payload only after a real first guard protects its held PID."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

p=SimpleNamespace(**runpy.run_path(str(Path(__file__).resolve().with_name("profile.py"))))
D=p.D
FIT=p.R/"incident-replay-fit-20261121-v1/tools-v4/post-stop-fit"
GUARD=p.GUARD/"tools/guard"
ALIAS=Path("/run/horizon-recovered170")
C=D/"controller"
SESSION=D/"controller-v3"
hold=SimpleNamespace(**runpy.run_path(str(Path(__file__).resolve().with_name("hold145.py"))))
ORIGINAL_SEAL="e5da777707c6ff70923de35b763ba939e9f275a59e9315c10f0b17ebb90e2941"
LOCK=Path("/run/horizon-epoch171-to136-g1.operation.lock")
UPLOAD=p.R/"epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2"

def run(argv,seconds=30):
    return subprocess.check_output([str(a) for a in argv],timeout=seconds)

def member(path,seal_sha):
    v,vr=p.read(path.parent/"deployment-seal-receipt.json",seal_sha)
    p.need(v["destination"]==str(path.parent) and any(x["name"]==path.name and x["sha256"]==p.digest(path) for x in v["members"]),
           "unexpected sealed member")
    return vr

def prepared():
    obj,pr=p.read(D/"PREPARED.json");original,pref=p.read(D/"profile.json",obj["profile"]["sha256"])
    fresh=p.profile(False)
    for note in original["projections"][1:]:
        match=next(x for x in fresh["projections"] if x["source"]==note["source"]);match["sha256"]=note["sha256"]
    p.need(original==fresh and obj["profile"]==pref,"retained inputs changed")
    return obj,pr,original,pref

def inventory():
    p.need(p.digest(UPLOAD)=="eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904","different inventory provider")
    v=json.loads(run([UPLOAD,"inventory","/home/sol/horizon","--epochs","170-170"],65))
    p.need(v["schema"]=="jetstreamer-horizon-r2-inventory-v1" and v["anomalies"]==0 and
           v["requested_epochs"]==v["missing"]==len(v["entries"])==1 and v["entries"][0]["state"]=="missing" and
           v["entries"][0]["epoch"]==170,"inventory does not justify a normal epoch 170 replay")
    return p.record(D/"INVENTORY_PRESTART.json",v)

def wait_for_145_window():
    # Each v5 verifier's synchronous self-check temporarily stops its leased child.
    # Align our capture with a fresh resumed interval. The fit then revalidates
    # the complete fleet and both lease sets without special-casing an extra PID.
    base=p.R/"epoch145-semantic-continuity-20261121-v1"
    record,_=p.read(base/"V5_ACTUAL_ADVANCING_WORKER.json","511cee5b1559001e5691eda9f9d9de923849dc4a3b661792cade776cad6e55d6")
    proof=record["observations"][-1];parent=proof["parent_pid"];child=proof["child_pid"]
    unit="horizon-holding-export145-20261121-v1.service";manager=p.show(unit)
    if manager["InvocationID"]!=record["invocation_id"] or manager["ActiveState"]!="active":return
    image=base/"tools-v5/export145";group="0::/system.slice/"+unit
    expected=sorted((parent,child));deadline=time.monotonic()+77;observed=False
    while time.monotonic()<deadline:
        if p.show(unit)["InvocationID"]!=record["invocation_id"] or not p.members(unit):return
        ids=p.members(unit)
        try:
            pp,ct,cg,_,_=p.native(child);_,pt,pg,_,_=p.native(parent)
        except (FileNotFoundError,ProcessLookupError):
            return
        p.need((pp,ct,cg,pt,pg)==(parent,proof["child_ticks"],group,proof["parent_ticks"],group) and
               all(Path(f"/proc/{pid}/exe").samefile(image) for pid in expected),"145 verifier identity changed")
        if observed and ids==expected:return
        for pid in set(ids)-set(expected):
            proc=Path(f"/proc/{pid}")
            try:
                if p.native(pid)[0]!=parent or not (proc/"exe").samefile("/usr/bin/python3"):continue
                a=[os.fsdecode(v) for v in (proc/"cmdline").read_bytes().split(b"\0") if v]
                tools=p.R/"incident-replay-fit-20261121-v1/tools-v3/post-stop-fit"
                if len(a)==6 and a[1:4]==["-IB",str(tools),"145"] and Path(a[4]).parent.parent==p.R and len(a[5])==64:
                    observed=True
            except (FileNotFoundError,ProcessLookupError):
                continue
        time.sleep(.20)
    raise ValueError("145 verifier did not leave a proven self-check interval")

def fit(fleet,seal_sha,stage=None):
    sr=member(FIT,seal_sha)
    if stage is None:wait_for_145_window()
    else:hold.check(stage)
    proc=subprocess.run([FIT,"170",fleet["path"],fleet["sha256"]],capture_output=True,timeout=150)
    if proc.returncode and not proc.stdout:
        raise ValueError("170 capacity capture failed: "+proc.stderr.decode(errors="replace")[-900:])
    v=json.loads(proc.stdout)
    p.need(proc.returncode==0 and v["schema"]=="horizon-incident-replay-fit-v1" and v["epoch"]==170 and v["fits"] and
           v["bookings"]["170"]["cap_bytes"]==p.CAP and v["epoch170_extension"]["extra_bytes"]==96<<30 and
           v["available_HOME_bytes"]>=v["complete_required_HOME_bytes"] and v["available_memory_bytes"]>=v["required_available_memory_bytes"],
           "384 GiB 170 trajectory is unfunded")
    return dict(v,provider_seal=sr)

def args(profile,pref):
    old,_=p.read(p.OLD/"ORIGINAL_PRODUCER_ARGV.json",p.ARGSHA);off=old.index(str(p.NODE));out=[];changed=0
    binds=[str(p.PKG)+":"+str(p.PKG)+":rbind",str(C/"gate.py")+":"+str(ALIAS/"gate.py"),
           str(D/"profile.json")+":"+str(ALIAS/"profile.json"),str(D/"barrier")+":"+str(ALIAS/"barrier")]
    binds.extend(v["source"]+":"+v["target"] for v in profile["projections"])
    for item in old[:off]:
        replacement=item
        if item=="--unit="+p.OLD_UNIT:replacement="--unit="+p.UNIT
        elif item=="--property=ReadWritePaths="+str(p.LANE):replacement="--property=ReadWritePaths="+str(p.RUN)
        elif item=="--property=BindReadOnlyPaths="+binds[0]:replacement="--property=BindReadOnlyPaths="+" ".join(binds)
        elif str(p.OLD_RUN) in item:replacement=item.replace(str(p.OLD_RUN),str(p.RUN))
        if replacement!=item:changed+=1
        out.append(replacement)
    ro="--property=BindReadOnlyPaths="+" ".join(binds)
    p.need(changed==6 and out[0]=="/usr/bin/systemd-run" and out.count(ro)==1 and
           not any(str(p.OLD_RUN) in a for a in out if a!=ro),"original mount or cgroup profile changed")
    return [*out,"--setenv=HORIZON_REPLAY170_PROFILE_SHA256="+pref["sha256"],"/usr/bin/python3","-IB",str(ALIAS/"gate.py"),*profile["normal_argv"]]

def observe(gated,iid=None):
    m=p.show(p.UNIT);pid=int(m["MainPID"]);ident=m["InvocationID"];proc=Path(f"/proc/{pid}")
    p.need(pid>1 and len(ident)==32 and ident!=p.IID and (iid is None or ident==iid) and m["ControlPID"]=="0" and
           m["ActiveState"]=="active" and m["SubState"]=="running" and m["CPUQuotaPerSecUSec"]=="9s" and
           m["MemoryMax"]==str(68<<30) and m["MemorySwapMax"]=="0" and m["NRestarts"]=="0" and not m["Job"],"different actual producer")
    _,ticks,group,dev,ino=p.native(pid);profile,_=p.read(D/"profile.json");arg=[os.fsdecode(a) for a in (proc/"cmdline").read_bytes().split(b"\0") if a]
    expected=profile["normal_argv"];source=p.NODE
    if gated:
        expected=["/usr/bin/python3","-IB",str(ALIAS/"gate.py"),*expected];source=Path("/usr/bin/python3")
        p.need(p.members(p.UNIT)==[pid] and (proc/"root"/str(ALIAS/"gate.py").lstrip("/")).samefile(C/"gate.py"),"unexpected held gate child or image")
    log=p.RUN/"producer.log"
    p.need(arg==expected and (proc/"exe").samefile(source) and group=="0::/system.slice/"+p.UNIT and
           (proc/"fd/1").samefile(log) and (proc/"fd/2").samefile(log) and log.stat().st_uid==0 and log.stat().st_ino==113710111 and
           p.native(pid)[1:]==(ticks,group,dev,ino),"foreign process or append descriptor")
    return dict(producer_unit=p.UNIT,producer_invocation_id=ident,producer_pid=pid,start_ticks=ticks,
                exe_device=dev,exe_inode=ino,cgroup=group[3:],MainPID=str(pid),InvocationID=ident,MainStartTicks=ticks)

def wait_actor(gated,iid=None,seconds=15):
    cutoff=time.monotonic()+seconds
    while True:
        try:return observe(gated,iid)
        except (ValueError,FileNotFoundError,ProcessLookupError):
            if time.monotonic()>=cutoff:raise
            time.sleep(.15)

def guard_args(cmd):
    old,_=p.read(p.OLD/"ORIGINAL_GUARD_ARGV.json",p.GARGSHA)
    at=next(i for i,a in enumerate(old) if a.endswith("/guard-v1/guard"))
    translated=[]
    for arg in old[:at]:
        if arg.startswith("--unit="):arg="--unit="+p.TIMER.removesuffix(".timer")
        elif arg.startswith("--property=ReadWritePaths="):arg="--property=ReadWritePaths="+str(D/"guard-receipts")
        elif arg.startswith("--property=StandardOutput="):arg="--property=StandardOutput=append:"+str(D/"guard.stdout")
        elif arg.startswith("--property=StandardError="):arg="--property=StandardError=append:"+str(D/"guard.stderr")
        translated.append(arg)
    return [str(a) for a in [*translated,*cmd]]

def configure_guard(actor,floor,binding,sha):
    gq,_=p.read(p.GUARD/"GUARD_QUALIFIED.json")
    p.need(binding==gq["contract"] and gq["guard"]["sha256"]==sha,"different qualified protection")
    ident=actor["producer_invocation_id"]
    plan=dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=p.UNIT,filesystem="/home/sol",invocation_id=ident,
              worker_root=str(p.LANE),maximum_root_physical_bytes=p.CAP,maximum_worker_vmas=3500000,minimum_free_bytes=floor,
              receipt_directory=str(D/"guard-receipts"),data_fulfillment=binding)
    pr=p.record(D/"ACTUAL_GUARD_PLAN.json",plan)
    cmd=[GUARD,pr["path"],"--plan-sha256",pr["sha256"],"--self-sha256",sha]
    value=json.loads(run([*cmd,"--validate-plan-only"]))
    p.need(value["validated"] and value["unit"]==p.UNIT and value["producer_signaled"] is False,"static guard validation failed")
    argv=guard_args(cmd)
    p.record(D/"GUARD_ARGV.json",argv)
    run(argv)
    return pr

def latest(actor,pr,require_worker,after=None):
    directory=D/"guard-receipts";m=p.show(p.TIMER);service=p.TIMER.removesuffix(".timer")+".service";g=p.show(service)
    p.need(m["ActiveState"]=="active" and m["Triggers"]==service and not m["Job"] and g["TriggeredBy"]==p.TIMER and
           g["MemoryMax"]==str(1<<30) and g["CPUQuotaPerSecUSec"]=="1s" and g["MemorySwapMax"]=="0" and
           not any(directory.glob("stop-*.json")),"changed native guard")
    samples=sorted(directory.glob("sample-*.json"),key=lambda q:q.stat().st_mtime_ns,reverse=True)
    p.need(samples,"await first timer-driven guard");v,sr=p.read(samples[0]);sid=v["guard_invocation_id"]
    p.need(len(sid)==32 and samples[0].name=="sample-"+sid+".json" and v["guard_sha256"]==p.digest(GUARD) and
           v["plan_sha256"]==pr["sha256"] and v["producer_invocation_id"]==actor["producer_invocation_id"] and
           v["producer"]["pid"]==actor["producer_pid"] and v["producer"]["cgroup"]=="/system.slice/"+p.UNIT and
           v["producer"]["active"]=="active" and v["producer_stop_enabled"] and v["trip_reason"] is None and
           v["DATA_fulfillment"] and v["DATA_fulfillment_observation_error"] is None and v["worker_observation_error"] is None and
           v["root_physical_observation_error"] is None and not v["root_physical_observation"]["exceeds_budget"] and
           0<=time.time()-v["recorded_unix_seconds"]<=90 and sid!=after,"await fresh native guard on same actor")
    if require_worker:p.need(len(v["workers"])==1 and 0<v["workers"][0][1]<3500000,"await native worker")
    j=run(["/usr/bin/journalctl","--no-pager","-ojson","--output-fields=UNIT,INVOCATION_ID,JOB_RESULT","_PID=1","UNIT="+service,"INVOCATION_ID="+sid,"-n12"])
    p.need(any(json.loads(l).get("JOB_RESULT")=="done" for l in j.splitlines()),"native guard did not complete")
    return dict(receipt=sr,timer=m,guard_invocation=sid,genuine_first_timer_driven_success=True,producer=p.show(p.UNIT)),v

def wait_guard(actor,pr,worker=False,after=None,seconds=90):
    deadline=time.monotonic()+seconds
    while True:
        try:return latest(actor,pr,worker,after)
        except (ValueError,FileNotFoundError):
            p.need(p.show(p.UNIT)["InvocationID"]==actor["producer_invocation_id"] and
                   not any((D/"guard-receipts").glob("stop-*.json")),"native protector stopped the expected actor")
            if time.monotonic()>=deadline:raise
            time.sleep(.45)

def protected_worker():
    ad,ar=p.read(D/"ACTUAL_ADMISSION_AND_PROTECTION.json");actor=observe(False,ad["producer_invocation_id"])
    proof,sample=wait_guard(actor,ad["actual_guard_plan"],True,seconds=80);wp=sample["workers"][0][0]
    parent,ticks,group,dev,ino=p.native(wp);exe=Path(f"/proc/{wp}/exe");image=exe.readlink()
    p.need(parent==actor["producer_pid"] and group=="0::/system.slice/"+p.UNIT and image.is_relative_to(p.RUN/"private") and
           image.name=="historical-worker" and exe.samefile(image) and p.digest(exe)==p.digest(p.WORKER) and
           p.members(p.UNIT)==sorted((parent,wp)) and p.native(wp)==(parent,ticks,group,dev,ino),"foreign historical worker")
    scratch=next(a for a in image.parents if a.name=="scratch")
    log=p.RUN/"producer.log";m=log.stat()
    row=dict(range="170",controller_unit=p.UNIT,producer_unit=p.UNIT,scratch_path=str(scratch),worker_executable_basename="historical-worker",
             expected_producer_invocation_id=ad["producer_invocation_id"],expected_controller_invocation_id=ad["producer_invocation_id"],
             append_log=dict(path=str(log),device=m.st_dev,inode=m.st_ino))
    return p.record(D/"FIRST_PROTECTED_WORKER.json",dict(**actor,epoch=170,admission=ar,observer_row=row,worker_guard=proof,
                    worker_pid=wp,worker_start_ticks=ticks,worker_sha256=p.digest(exe),transaction_replay_claimed=False))

def start(fleet,seal):
    lock=open(LOCK,"r+b");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    obj,pr,profile,pref=prepared();controller=member(C/"gate.py",ORIGINAL_SEAL)
    session=member(SESSION/"session.py",p.digest(SESSION/"deployment-seal-receipt.json"))
    p.need(p.show(p.UNIT)["LoadState"]=="not-found" and p.show(p.TIMER)["LoadState"]=="not-found" and
           not (D/"START_INTENT.json").exists() and not (D/"barrier/allow").exists() and not list((D/"guard-receipts").iterdir()) and
           not list((p.RUN/"private").iterdir()) and (p.RUN/"producer.log").stat().st_size==0,"prior attempt or occupied successor")
    inv=inventory();pre=fit(fleet,seal);ext=pre["epoch170_extension"]
    def interrupted(signum,frame):raise TimeoutError("independent 145 thaw deadline")
    original=signal.signal(signal.SIGTERM,interrupted)
    try:
        stage=hold.begin()
        try:return activate(fleet,seal,obj,pr,profile,pref,controller,session,inv,pre,ext,stage)
        finally:hold.finish(stage)
    finally:signal.signal(signal.SIGTERM,original)

def activate(fleet,seal,obj,pr,profile,pref,controller,session,inv,pre,ext,stage):
    hold.check(stage)
    book=p.record(D/"ACCEPTED_384_BOOKING.json",dict(epoch=170,cap_bytes=p.CAP,extra_bytes=96<<30,retired=ext["retired"],guard=ext["guard"],prestart=pre))
    floor=min(pre["available_HOME_bytes"],pre["protected_raw_floor_bytes"]+(128<<20))
    intent=p.record(D/"START_INTENT.json",dict(schema="horizon-170-recovery-start-intent-v1",epoch=170,producer_unit=p.UNIT,timer_unit=p.TIMER,
            prepared=pr,fleet=fleet,prestart=pre,armed_floor=floor,authenticated_inventory=inv,stable_root=obj["stable_root"],
            predecessor_stop=obj["predecessor_stop"],controller=controller,actual_session=session,verifier_hold=p.read(stage/"HELD.json")[1],booking=book,recorded_unix_seconds=int(time.time()),resource_credit_bytes=0))
    argv=args(profile,pref);p.record(D/"PRODUCER_ARGV.json",argv);iid=None
    try:
        run(argv);held=wait_actor(True);iid=held["producer_invocation_id"];p.record(D/"NATIVE_GATED.json",held)
        q,_=p.read(p.GUARD/"GUARD_QUALIFIED.json");plan=configure_guard(held,floor,q["contract"],q["guard"]["sha256"])
        first,_=wait_guard(held,plan);fr=p.record(D/"FIRST_GUARD.json",first)
        post=fit(fleet,seal,stage);p.need(post["candidate"]["producer_invocation_id"]==iid and
              post["protected_raw_floor_bytes"]<=floor and observe(True,iid)==held,"post-guard protection changed")
        postref=p.record(D/"POST_GUARD_CAPACITY.json",post)
        p.record(D/"AUTHORIZED_GATED_PAYLOAD.json",dict(**held,first_guard=fr,plan=plan,capacity=postref,intent=intent))
        hold.check(stage)
        permit=D/"barrier/allow"
        temp=D/"barrier"/("."+iid)
        with temp.open("xb") as f:os.fchmod(f.fileno(),0o444);f.write(iid.encode());f.flush();os.fsync(f.fileno())
        os.rename(temp,permit);p.fsyncdir(permit.parent)
        actor=wait_actor(False,iid);p.need(actor["producer_pid"]==held["producer_pid"] and actor["start_ticks"]==held["start_ticks"],"gate PID changed")
        p.record(D/"ACTUAL_PRODUCER_NATIVE.json",actor)
        proof,_=wait_guard(actor,plan,after=first["guard_invocation"])
        p.need(proof["timer"]["InvocationID"]==first["timer"]["InvocationID"],"timer replaced at exec")
        hold.check(stage)
        return p.record(D/"ACTUAL_ADMISSION_AND_PROTECTION.json",dict(**actor,epoch=170,timer_unit=p.TIMER,timer_invocation_id=proof["timer"]["InvocationID"],
                actual_guard_plan=plan,first_guard=fr,post_guard_capacity=postref,bootstrap_only=True,transaction_replay_claimed=False,
                fleet=fleet,intent=intent,stable_root=obj["stable_root"],predecessor_stop=obj["predecessor_stop"],source=pr,resource_credit_bytes=0))
    except BaseException as error:
        if iid is None and p.members(p.UNIT):
            # Roll back only a gate whose open inode/argv, permanent root and typed PID
            # can be authenticated even if the service appeared after systemd-run timed out.
            iid=wait_actor(True,seconds=3)["producer_invocation_id"]
        if iid and p.show(p.UNIT)["InvocationID"]==iid:
            run(["/usr/bin/systemctl","stop",p.UNIT])
            if p.show(p.TIMER)["ActiveState"]=="active":run(["/usr/bin/systemctl","stop",p.TIMER])
        p.record(D/"START_FAILURE.json",dict(epoch=170,error=str(error),producer_invocation_id=iid,intent=intent,cgroup=p.members(p.UNIT),partial_retained=True))
        raise

def main():
    p.need(os.geteuid()==0 and sys.flags.isolated and __debug__,"root isolated session required")
    if sys.argv[1:]==["prepare"]:return p.prepare()
    p.need(Path(__file__).resolve()==SESSION/"session.py","use sealed 170 controller")
    if sys.argv[1:]==["record-worker"]:return protected_worker()
    mode,path,sha,seal=sys.argv[1:];_,fleet=p.read(Path(path),sha)
    if mode=="preflight":prepared();return fit(fleet,seal)
    p.need(mode=="start","unexpected mode")
    return start(fleet,seal)

if __name__=="__main__":print(json.dumps(main(),sort_keys=True))
