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
if __name__=="__main__" and (HERE != Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v4") or not sys.flags.isolated):
    raise SystemExit("use the sealed root session with python3 -IB")
sys.path.insert(0,str(HERE))
import fit
import incident
import status168 as s

D=s.D
BACKING=Path("/home/sol/.jetstreamer-private/horizon-root-runtime-data")/D.name
OP_LOCK="/run/horizon-epoch171-to136-g1.operation.lock"
PACKAGE=D/"session-v4"
SEALER="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
INPUTS=("session.py","fit.py","status168.py","overlap.py","same_five.py","same-five-image.json","incident.py","incident-fit.json")


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
    artifact,ar=s.read(D/"SESSION_DEPLOYMENT_V4.json")
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


def stable_root():
    witness=s.bound(incident.ROOTS,D/"STABLE_167_168_ROOTS_BEFORE_DATA_WITNESS.json")
    row=witness["normal168"]
    st=s.RUN.lstat()
    s.need(witness["preserved_witness_files"]==12 and row["path"]==str(s.RUN)
           and s.RUN.resolve(strict=True)==s.RUN and stat.S_ISDIR(st.st_mode)
           and (st.st_dev,st.st_ino)==(row["device"],row["inode"])
           and not (D/"prepared-run").exists(),"different permanent normal 168 directory")
    return dict(device=st.st_dev,inode=st.st_ino)


def append_log(archive=None):
    identity=stable_root()
    for unit in (s.U,s.GUARD+".service",s.T):
        m=s.show(unit)
        s.need(m["ActiveState"] in ("failed","inactive") and m.get("MainPID","0") in ("","0") and
               not m["Job"] and not fit.members(unit),"168 log still in use")
    witness=s.bound(incident.ROOTS,D/"STABLE_167_168_ROOTS_BEFORE_DATA_WITNESS.json")
    prior=witness["closed_168_intent"]
    prior_path=Path(prior["path"])
    s.need(prior_path.parent.parent==D and prior_path.parent.name.startswith("abandoned-gate-") and
           s.bound(prior,prior_path)["run_tree"]==stable_root(),"wrong abandoned 168 generation")
    fd=os.open(s.LOG,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"r+b") as log:
        m=os.fstat(fd)
        s.need(stat.S_ISREG(m.st_mode) and (m.st_dev,m.st_ino,m.st_nlink,stat.S_IMODE(m.st_mode))==
               (64512,103350639,1,0o600) and (m.st_uid,m.st_gid) in ((1001,1003),(0,0))
               and s.LOG.resolve(strict=True)==s.LOG and os.path.samestat(m,s.LOG.lstat()),"wrong original 168 log")
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_WRLCK)
        try:
            if m.st_size:
                s.need(archive is not None and (m.st_uid,m.st_gid)==(0,0) and m.st_size<=16<<20,
                       "unexpected contents in held gate log")
                data=log.read(m.st_size+1)
                s.need(len(data)==m.st_size,"gate log changed")
                put(archive/"producer.log",data,0o400)
                os.ftruncate(fd,0)
            if (m.st_uid,m.st_gid)!=(0,0):
                os.fchown(fd,0,0)
            os.fsync(fd)
            final=os.fstat(fd)
            s.need(final.st_size==0 and (final.st_uid,final.st_gid)==(0,0)
                   and os.path.samestat(final,s.LOG.lstat()) and stable_root()==identity,
                   "different observer log after preparation")
        finally:
            fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
    return record("OBSERVER_LOG_V4.json",dict(path=str(s.LOG),device=m.st_dev,inode=m.st_ino,
                  stable_root=incident.ROOTS,previous_intent=prior,uid=0,gid=0,mode=0o600))


def ready_tree(root,j,p):
    files,dirs=paths(j,p)
    prep=s.read(D/"PREPARED.json",s.PREPARED)[0]
    s.need(root.resolve(strict=True)==root and {Path(n) for n in prep["ready_entries"]}==files|dirs
           and {Path("."),*(x.relative_to(root) for x in root.rglob("*"))}==files|dirs,"different staged normal tree")
    for n in files|dirs:
        m=(root/n).lstat()
        owner=(0,0) if n==Path("producer.log") else (1001,1003)
        s.need((m.st_uid,m.st_gid)==owner and (n!=Path("producer.log") or (m.st_dev,m.st_ino)==(64512,103350639)) and ((n in dirs and stat.S_ISDIR(m.st_mode)
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
    s.need(not (D/"barrier/allow").exists() and not (D/"START_INTENT.json").exists()
           and not (D/"ACTUAL_ADMISSION_AND_PROTECTION.json").exists() and not any((D/"guard-receipts").iterdir())
           and all(s.show(n)["LoadState"]=="not-found" for n in (s.U,s.T,s.GUARD+".service")),
           "different or already-partially-created 168 admission")
    identity=stable_root()
    s.need(ready_tree(s.RUN,j,p)==identity and s.same_file(BACKING,D) and
           s.TREE.resolve(strict=True)==s.TREE and s.TREE.stat().st_dev==identity["device"],"wrong 168 backing")
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
    s.need(stable_root()==intent["run_tree"],"previous gate used a different permanent root")
    append_log(archive)
    s.need(ready_tree(s.RUN,j,reg.p)==intent["run_tree"],"occupied or foreign previous gate tree")
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
    inventory_ref=inventory()
    pre=incident.capture(fleetref)
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
        s.need(ready_tree(s.RUN,j,reg.p)==tree and incident.unchanged(pre),"prestart authority changed")
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
        post=incident.capture(fleetref,actor)
        fit.select(pre,post,floor)
        cr=record("POST_GUARD_CAPACITY.json",post)
        record("AUTHORIZED_GATED_PAYLOAD.json",dict(**actor,epoch=168,first_guard=fr,actual_guard_plan=pr,
                  post_guard_capacity=cr,fleet=fleetref,bootstrap_only=True,transaction_replay_claimed=False,root_session=deployment,
                  registered_status=pre["status_registration"],authenticated_inventory=inventory_ref,archive_publication_authorized=False,r2_mutations=False))
        still_held()
        latest=native_first(actor,pr)
        s.need(latest["timer"]["InvocationID"]==t["InvocationID"] and incident.unchanged(post,actor),"late membership change")
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
    parser.add_argument("mode",choices=("prepare-log","preflight","start","record-worker"))
    parser.add_argument("session_seal_sha")
    parser.add_argument("--fleet",type=Path)
    parser.add_argument("--fleet-sha")
    args=parser.parse_args()
    os.umask(0o077)
    reg,deployment=controller(s.ref(PACKAGE/"deployment-seal-receipt.json",args.session_seal_sha))
    with open(OP_LOCK,"a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.mode=="prepare-log":
            s.need(s.inspect() is None and not (D/"barrier/allow").exists(),"168 session already active")
            result=append_log()
            prepared(reg.p.normal_spec()[0],reg.p)
        elif args.mode=="record-worker": result=worker(20)
        else:
            s.need(args.fleet and args.fleet_sha,"supply fresh root fleet path and digest")
            fleet=s.ref(args.fleet,args.fleet_sha)
            result=incident.capture(fleet) if args.mode=="preflight" else launch(reg,deployment,fleet)
    if args.mode=="start" and not (D/"FIRST_PROTECTED_WORKER.json").exists():
        # The producer now owns its paid reservation. Monitoring can be resumed with record-worker.
        result=dict(admission=result,first_worker=worker(300))
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
