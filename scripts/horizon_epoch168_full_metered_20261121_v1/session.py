#!/usr/bin/python3 -I
"""Root's preflight, guarded bootstrap, and first protected worker for normal epoch 168."""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent
if __name__=="__main__" and (HERE != Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v1") or not sys.flags.isolated):
    raise SystemExit("use the sealed root session with python3 -IB")
sys.path.insert(0,str(HERE))
import fit
import status168 as s

D=s.D
BACKING=Path("/home/sol/.jetstreamer-private/horizon-root-runtime-data")/D.name
OP_LOCK="/run/horizon-epoch171-to136-g1.operation.lock"
PACKAGE=D/"session-v1"
SEALER="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
INPUTS=("session.py","fit.py","status168.py","overlap.py")


def sync(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def put(path,data,mode):
    tmp=path.with_name("."+path.name+"-"+uuid.uuid4().hex)
    try:
        with tmp.open("xb") as f:
            os.fchmod(f.fileno(),mode)
            f.write(data);f.flush();os.fsync(f.fileno())
        # renameat2 avoids a momentary second hard link to a root permit/evidence file.
        try: move(tmp,path)
        except FileExistsError:
            m=path.lstat()
            s.need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and stat.S_IMODE(m.st_mode)==mode
                   and m.st_nlink==1 and path.read_bytes()==data,"conflicting prior "+str(path))
    finally: tmp.unlink(missing_ok=True)


def move(src,dst):
    f=ctypes.CDLL(None,use_errno=True).renameat2
    f.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    # Open and pin both parents before the nonreplacing rename.
    a=os.open(src.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        b=os.open(dst.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            if f(a,os.fsencode(src.name),b,os.fsencode(dst.name),1):
                e=ctypes.get_errno()
                raise OSError(e,os.strerror(e),str(dst))
            os.fsync(a);os.fsync(b)
        finally: os.close(b)
    finally: os.close(a)


def record(name,obj):
    data=(json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()
    put(D/name,data,0o444)
    return s.ref(D/name,hashlib.sha256(data).hexdigest())


def controller(sealref):
    s.need(os.geteuid()==0 and HERE==PACKAGE and sys.flags.isolated,"use root isolated sealed epoch 168 session")
    artifact,ar=s.read(D/"SESSION_DEPLOYMENT.json")
    seal=s.bound(sealref,HERE/"deployment-seal-receipt.json")
    s.need(artifact["seal"]==sealref and artifact["source_commit"] and artifact["branch"]=="account-updates"
           and seal["sealer_sha256"]==SEALER and seal["destination"]==str(HERE)
           and {x["name"] for x in seal["members"]}==set(INPUTS),"incomplete normal session deployment")
    for row in seal["members"]:
        s.need(artifact["members"][row["name"]]==row["sha256"],"wrong branch session member")
        fit.binary(HERE/row["name"],row["sha256"])
    c=D/"controller"
    old=s.read(c/"deployment-seal-receipt.json",s.CONTROLLER)[0]
    s.need({r["name"] for r in old["members"]}=={"registration.py","production.py","gate.py"},"wrong normal controller")
    for r in old["members"]: fit.binary(c/r["name"],r["sha256"])
    m=importlib.util.spec_from_file_location("registration",c/"registration.py")
    reg=importlib.util.module_from_spec(m)
    m.loader.exec_module(reg)
    return reg,ar


def paths(j,production):
    files={s.RUN/"producer.log",*(t for t in production.projection(j) if t.is_relative_to(s.RUN))}
    dirs={s.RUN,s.RUN/"private",s.RUN/"runtime",s.RUN/"ledger"}
    for p in files: dirs.update(q for q in p.parents if q.is_relative_to(s.RUN))
    return ({p.relative_to(s.RUN) for p in files},{p.relative_to(s.RUN) for p in dirs})


def ready_tree(root,j,p):
    files,dirs=paths(j,p)
    prep=s.read(D/"PREPARED.json",s.PREPARED)[0]
    s.need(root.resolve(strict=True)==root and {Path(n) for n in prep["ready_entries"]}==files|dirs
           and {Path("."),*(x.relative_to(root) for x in root.rglob("*"))}==files|dirs,"different staged normal tree")
    for n in files|dirs:
        m=(root/n).lstat()
        s.need(m.st_uid==1001 and m.st_gid==1003 and ((n in dirs and stat.S_ISDIR(m.st_mode)
               and stat.S_IMODE(m.st_mode)==0o700) or (n in files and stat.S_ISREG(m.st_mode) and
               stat.S_IMODE(m.st_mode)==0o600 and m.st_size==0 and m.st_nlink==1)), "occupied 168 staging tree")
    return dict(device=root.stat().st_dev,inode=root.stat().st_ino)


def native_first(actor,planref,want_worker=False):
    unit,ident=s.native_actor(s.read(D/"START_INTENT.json")[0],node=want_worker)
    s.identity(ident,actor)
    proof,sample=s.receipt(actor,planref,want_worker)
    service=s.GUARD+".service"
    g=s.show(service); t=s.show(s.T)
    s.need(g["Result"]=="success" and g["ExecMainStatus"]=="0"
           and proof["timer"]["InvocationID"]==t["InvocationID"] and g["InvocationID"]==proof["guard_invocation"],
           "guard is between timer firings")
    cmd=fit.command("/usr/bin/systemctl","show",service,"-p","ExecStart","--value")
    plan=planref["path"]
    native=s.ROOT/"epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
    expected=f"{{ path={native} ; argv[]={native} {plan} --plan-sha256 {planref['sha256']} --self-sha256 {s.GIMAGE} ;"
    s.need(cmd.startswith(expected) and cmd.count(" ; argv[]=")==1,"different guard command")
    dbus="/org/freedesktop/systemd1/unit/"+''.join(c if c.isalnum() else f"_{ord(c):02x}" for c in s.T)
    trigger=fit.command("/usr/bin/busctl","--system","--timeout=5s","get-property","org.freedesktop.systemd1",
                        dbus,"org.freedesktop.systemd1.Timer","LastTriggerUSecMonotonic").split()
    start=int(fit.command("/usr/bin/systemctl","show",service,"-p","ExecMainStartTimestampMonotonic","--value"))
    s.need(trigger[0]=="t" and 0<int(trigger[1])<=start<=int(trigger[1])+4000000 and
           (want_worker or sample["workers"]==[]),"not the native timer fire at the held gate")
    return dict(proof,producer=unit,genuine_first_timer_driven_success=not want_worker)


def wait_for(predicate,seconds,recheck,interval=.3):
    until=time.monotonic()+seconds
    last=None
    while time.monotonic()<until:
        recheck()
        try: return predicate()
        except (ValueError,FileNotFoundError,StopIteration,subprocess.CalledProcessError) as e:
            last=e
        time.sleep(interval)
    raise ValueError("epoch 168 condition expired: "+str(last))


def prepared(j,p):
    s.need(not s.RUN.exists() and (D/"barrier/allow").exists() is False and not any((D/"guard-receipts").iterdir())
           and all(s.show(n)["LoadState"]=="not-found" for n in (s.U,s.T,s.GUARD+".service")),
           "different or already-partially-created 168 admission")
    identity=ready_tree(D/"prepared-run",j,p)
    s.need(s.same_file(BACKING,D) and s.same_file(BACKING/"prepared-run",D/"prepared-run")
           and s.TREE.resolve(strict=True)==s.TREE and s.TREE.stat().st_dev==identity["device"],
           "wrong HOME backing for normal 168")
    return identity


def recover(reg):
    if (D/"barrier/allow").exists():
        # A released generation is never rolled back. Only its matching original recorder can finish the transaction.
        value=(D/"barrier/allow").read_bytes()
        auth=s.read(D/"AUTHORIZED_GATED_PAYLOAD.json")[0]
        s.need(value==auth["producer_invocation_id"].encode(),"different existing permit")
        wait_for(reg.main,20,lambda: None)
        return True
    if not (D/"START_INTENT.json").exists(): return False
    intent,_=s.read(D/"START_INTENT.json")
    j,argv=reg.p.normal_spec()
    u=s.show(s.U);t=s.show(s.T)
    if u["ActiveState"] in ("active","activating"):
        _,actor=s.native_actor(intent)
        if (D/"NATIVE_GATED.json").exists():
            s.identity(s.read(D/"NATIVE_GATED.json")[0],actor)
        s.need(u["InvocationID"]==actor["producer_invocation_id"],"crossed prior gate")
    if t["ActiveState"]=="active":
        plan,pr=s.read(D/"ACTUAL_GUARD_PLAN.json")
        expected,cmd=reg.p.guard(j,plan["invocation_id"],plan["minimum_free_bytes"])
        s.need(plan==expected and s.bound(s.read(D/"SESSION_GUARD_ARGV.json")[1],D/"SESSION_GUARD_ARGV.json")==cmd
               and t["Description"].endswith(f"--plan-sha256 {pr['sha256']} --self-sha256 {s.GIMAGE}")
               and t["Triggers"]==s.GUARD+".service","foreign prior 168 timer")
        if (D/"NATIVE_GATED.json").exists():
            g=s.read(D/"NATIVE_GATED.json")[0]
            s.need(t["InvocationID"]==g["timer_invocation_id"] and g["producer_invocation_id"]==plan["invocation_id"],
                   "different recorded 168 timer")
        subprocess.run(["/usr/bin/systemctl","stop",s.T],timeout=25,check=True)
        # A guard already running completes on its own. The operation never stops a foreign unit name.
        wait_for(lambda: _drain_guard(),30,lambda: None)
    if u["ActiveState"] in ("active","activating"):
        u2=s.show(s.U)
        s.need(u2["InvocationID"]==u["InvocationID"] and u2["Description"]=="guarded-full168-metered-"+intent["token"],
               "different 168 gate during recovery")
        subprocess.run(["/usr/bin/systemctl","stop",s.U],timeout=60,check=True)
    for n in (s.T,s.GUARD+".service",s.U):
        m=s.show(n)
        s.need(m["ActiveState"] in ("inactive","failed") and not m["Job"] and not fit.members(n),"previous 168 not drained")
        if m["ActiveState"]=="failed": subprocess.run(["/usr/bin/systemctl","reset-failed",n],check=True,timeout=15)
    archive=D/("abandoned-gate-"+intent["token"]);archive.mkdir(mode=0o700,exist_ok=True)
    if s.RUN.exists():
        m=s.RUN.lstat()
        s.need((m.st_dev,m.st_ino)==(intent["run_tree"]["device"],intent["run_tree"]["inode"])
               and s.RUN.resolve(strict=True)==s.RUN,"foreign previous run path")
        log=s.RUN/"producer.log";saved=BACKING/archive.name/"producer.log"
        if log.exists() and log.lstat().st_size:
            m=log.lstat()
            s.need(stat.S_ISREG(m.st_mode) and m.st_uid==1001 and m.st_nlink==1,"wrong gate log")
            move(log,saved)
        if not log.exists() and saved.exists():
            with log.open("xb") as f:
                os.fchown(f.fileno(),1001,1003);os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
            sync(s.RUN)
        s.need(ready_tree(s.RUN,j,reg.p)==intent["run_tree"] and not (D/"prepared-run").exists(),"occupied or foreign previous gate tree")
        move(s.RUN,BACKING/"prepared-run")
    s.need(ready_tree(D/"prepared-run",j,reg.p)==intent["run_tree"],"different staged root on recovery")
    # Move the intent last. Its presence lets an interrupted cleanup resume against the same generation.
    for n in ("SESSION_PRODUCER_ARGV.json","NATIVE_GATED.json","ACTUAL_GUARD_PLAN.json","SESSION_GUARD_ARGV.json",
              "FIRST_GUARD.json","POST_GUARD_CAPACITY.json","AUTHORIZED_GATED_PAYLOAD.json","guard.stdout","guard.stderr"):
        if (D/n).exists(): move(D/n,archive/n)
    rec=D/"guard-receipts"
    if rec.exists() and list(rec.iterdir()): move(rec,archive/rec.name)
    rec.mkdir(mode=0o700,exist_ok=True)
    move(D/"START_INTENT.json",archive/"START_INTENT.json")
    return False


def _drain_guard():
    unit=s.show(s.GUARD+".service")
    s.need(unit["ActiveState"] in ("inactive","failed") and not unit["Job"] and not fit.members(s.GUARD+".service"),
           "168 guard still completing")


def inventory():
    src=Path("/home/sol/.jetstreamer-private/epoch172-independent-singleton-20261110-v1/ADMISSION_INVENTORY-ORIGINAL-ARGV.json")
    template=s.read(src,"ecf370dc0da1a47ddcee8a46bf2d6905d05500244993c69de0f236358bd105ee")[0]
    s.need(template[-4:]==["inventory","/home/sol/horizon","--epochs","101-200"],"different original inventory operation")
    nonce=uuid.uuid4().hex
    target=D/("inventory-"+nonce+".json")
    argv=[]
    for item in template:
        if item.startswith("--unit="): item="--unit=horizon-full168-readonly-inventory-"+nonce
        elif item=="CPUQuota=200%": item="CPUQuota=25%"
        elif item.startswith("ReadWritePaths="): item="ReadWritePaths="+str(D)
        elif item.startswith("StandardOutput=file:"): item="StandardOutput=file:"+str(target)
        elif item=="101-200": item="168-168"
        argv.append(item)
    subprocess.run(argv,check=True,timeout=150)
    result,ref=s.read(target)
    s.need(result["schema"]=="jetstreamer-horizon-r2-inventory-v1" and result["anomalies"]==0
           and result["requested_epochs"]==result["missing"]==1 and len(result["entries"])==1
           and result["entries"][0]["epoch"]==168 and result["entries"][0]["state"]=="missing",
           "epoch 168 already present or inventory differs")
    return ref


def launch(reg,deployment,fleetref):
    if recover(reg): return s.read(D/"ACTUAL_ADMISSION_AND_PROTECTION.json")[1]
    j,argv=reg.p.normal_spec()
    tree=prepared(j,reg.p)
    pre=fit.capture(fleetref)
    fit.select(pre)
    inventory_ref=inventory()
    pre=fit.capture(fleetref)
    floor=fit.select(pre)
    floor=min(pre["available_HOME_bytes"],floor+(128<<20))
    token=uuid.uuid4().hex
    argv=list(argv);i=argv.index("--description=guarded-full168-metered")
    argv[i]+="-"+token
    intent=dict(schema="horizon-168-normal-start-intent-v1",epoch=168,token=token,recorded_unix_seconds=int(time.time()),
                expires_in_seconds=180,run_tree=tree,producer_unit=s.U,timer_unit=s.T,prepared=s.ref(D/"PREPARED.json",s.PREPARED),
                prior_trace_terminal=s.ref(s.TRACE,s.CLOSED),status_registration=pre["status_registration"],prestart=pre,
                root_session=deployment,authenticated_inventory=inventory_ref,armed_floor=floor,resource_credit_bytes=0,transaction_replay_claimed=False)
    ir=record("START_INTENT.json",intent)
    try:
        record("SESSION_PRODUCER_ARGV.json",argv)
        move(BACKING/"prepared-run",s.RUN)
        s.need(ready_tree(s.RUN,j,reg.p)==tree and fit.phase145()==(pre["phase145"],True)
               and fit.status_ready()==pre["status_registration"],"prestart authority changed")
        subprocess.run(argv,check=True,timeout=30)
        u,actor=wait_for(lambda:s.native_actor(intent),10,lambda:None)
        generation=actor["producer_invocation_id"]
        plan,guard=reg.p.guard(j,generation,floor)
        pr=record("ACTUAL_GUARD_PLAN.json",plan)
        i=guard.index("--plan-sha256")
        static=json.loads(fit.command(*guard[i-2:],"--validate-plan-only"))
        s.need(static["validated"] and static["unit"]==s.U and not static["producer_signaled"],"168 guard plan rejected")
        record("SESSION_GUARD_ARGV.json",guard)
        subprocess.run(guard,check=True,timeout=30)
        t=s.show(s.T)
        s.need(t["ActiveState"]=="active" and t["Triggers"]==s.GUARD+".service" and s.iid(t["InvocationID"]),"unbound new 168 timer")
        record("NATIVE_GATED.json",dict(**actor,intent=ir,timer_unit=s.T,timer_invocation_id=t["InvocationID"],actual_guard_plan=pr))
        def still_held():
            s.need(not (D/"barrier/allow").exists() and time.time()-intent["recorded_unix_seconds"]<177,"168 gate no longer held")
            s.identity(s.native_actor(intent)[1],actor)
        first=wait_for(lambda:native_first(actor,pr),70,still_held)
        fr=record("FIRST_GUARD.json",first)
        post=fit.capture(fleetref,actor)
        fit.select(pre,post,floor)
        cr=record("POST_GUARD_CAPACITY.json",post)
        record("AUTHORIZED_GATED_PAYLOAD.json",dict(**actor,epoch=168,first_guard=fr,actual_guard_plan=pr,
                  post_guard_capacity=cr,fleet=fleetref,bootstrap_only=True,transaction_replay_claimed=False,root_session=deployment,
                  registered_status=pre["status_registration"],authenticated_inventory=inventory_ref,archive_publication_authorized=False,r2_mutations=False))
        still_held()
        latest=native_first(actor,pr)
        s.need(latest["timer"]["InvocationID"]==t["InvocationID"] and fit.phase145()==(pre["phase145"],True)
               and fit.status_ready()==pre["status_registration"] and
               fit.membership(post["incumbents"],actor,post["candidate136"])==pre["population"],"late membership change")
        put(D/"barrier/allow",generation.encode(),0o444)
        wait_for(lambda:s.native_actor(intent,node=True),20,lambda: None)
        wait_for(reg.main,20,lambda: None)
        return s.read(D/"ACTUAL_ADMISSION_AND_PROTECTION.json")[1]
    except BaseException:
        if not (D/"barrier/allow").exists(): recover(reg)
        raise


def worker(wait):
    intent=s.read(D/"START_INTENT.json")[0]
    ad,ar=s.read(D/"ACTUAL_ADMISSION_AND_PROTECTION.json")
    _,actor=s.native_actor(intent,node=True)
    s.identity(ad,actor)
    if (D/"FIRST_PROTECTED_WORKER.json").exists():
        s.need(s.inspect()["stage"]=="protected-worker","worker generation changed")
        return s.read(D/"FIRST_PROTECTED_WORKER.json")[1]
    def observe():
        row=s.worker_record(actor,ad["actual_guard_plan"])
        s.identity(s.native_actor(intent,node=True)[1],actor)
        return row
    gathered=wait_for(observe,wait,lambda:s.identity(s.native_actor(intent,node=True)[1],actor),interval=2)
    return record("FIRST_PROTECTED_WORKER.json",dict(gathered,admission=ar,epoch=168,
               measured_transaction_replay=False,archive_publication_authorized=False,resource_credit_bytes=0))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("preflight","start","record-worker"))
    parser.add_argument("session_seal_sha")
    parser.add_argument("--fleet",type=Path)
    parser.add_argument("--fleet-sha")
    args=parser.parse_args()
    os.umask(0o077)
    reg,deployment=controller(s.ref(PACKAGE/"deployment-seal-receipt.json",args.session_seal_sha))
    with open(OP_LOCK,"a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.mode=="record-worker": result=worker(20)
        else:
            s.need(args.fleet and args.fleet_sha,"supply fresh root fleet path and digest")
            fleet=s.ref(args.fleet,args.fleet_sha)
            result=fit.capture(fleet) if args.mode=="preflight" else launch(reg,deployment,fleet)
    if args.mode=="start" and not (D/"FIRST_PROTECTED_WORKER.json").exists():
        # The producer now owns its paid reservation. Monitoring can be resumed with record-worker.
        result=dict(admission=result,first_worker=worker(300))
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
