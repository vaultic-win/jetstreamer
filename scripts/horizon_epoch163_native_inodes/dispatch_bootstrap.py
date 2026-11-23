"""ROOT's one-shot, source-only bootstrap dispatch on the already priced serial slot."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
base=runpy.run_path(str(HERE/"bootstrap.py"))
fit=base["fit"]
need=fit["need"]
BASE,WORK,IMAGE,SOURCE,PACKAGE=(base[k] for k in ("BASE","WORK","IMAGE","SOURCE","PACKAGE"))
SLICE,SLICE_DIR,ROOT_UNIT=fit["SLICE"],fit["SLICE_DIR"],base["ROOT_UNIT"]
MIB=1<<20
SEAL=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")


def run(args):
    return subprocess.check_output(list(map(str,args)),text=True,timeout=25).strip()


def encode(v):
    return (json.dumps(v,sort_keys=True)+"\n").encode()


def git(*args):
    return subprocess.check_output(["/usr/sbin/runuser","-u","sol","--","/usr/bin/git","-C",str(HERE.parents[1]),*args])


def source(commit):
    import re
    need(re.fullmatch("[a-f0-9]{40}",commit) and git("rev-parse","HEAD").decode().strip()==commit and
         not git("merge-base","--is-ancestor",commit,"origin/account-updates"),"build sources not merged")
    for n in ("bootstrap.py","bootstrap_fit.py","dispatch_bootstrap.py","consumer_capacity.rs",
              "current-operator.patch","stage_native48.py"):
        need(git("show",commit+":scripts/horizon_epoch163_native_inodes/"+n)==(HERE/n).read_bytes(),
             "checkout changed: "+n)


def seal(plan):
    pin=fit["pin"]
    v=json.loads(plan.read_bytes())
    path=Path(v["destination"])
    digest=base["file_sha"](plan)
    pin(SEAL,base["SEALER"])
    if not path.exists():
        run([SEAL,plan,"--plan-sha256",digest,"--self-sha256",base["SEALER"]])
    h=base["file_sha"](path/"deployment-seal-receipt.json")
    r=fit["checked"]({"path":str(path/"deployment-seal-receipt.json"),"sha256":h})
    need(r["plan_sha256"]==digest,"different existing deployment")
    base["package"](path,h,[p["name"] for p in v["members"]])
    return h


def packages(commit):
    out=BASE/"bootstrap-prepared"
    source(commit)
    if not out.exists():
        out.mkdir(mode=0o700)
    need(out.resolve(strict=True)==out and out.stat().st_uid==0 and out.stat().st_mode&0o077==0,"unsafe preparation")
    stage=out/"operator-inputs"
    if not stage.exists():
        subprocess.run(["/usr/bin/python3","-IB",str(HERE/"stage_native48.py"),"operator","--current-fleet",
                        "/home/sol/.jetstreamer-private/epoch163-inode-repair-20261123/actor-ready/actor-source-plan.json",
                        str(stage)],check=True,timeout=40)
    operator_sha=seal(stage/"operator-source-plan.json")
    names=("bootstrap.py","bootstrap_fit.py")
    files=[]
    for n in names:
        target=out/n
        data=git("show",commit+":scripts/horizon_epoch163_native_inodes/"+n)
        if not target.exists():
            base["write"](target,data)
        need(target.read_bytes()==data,"changed prepared bootstrap")
        files.append(dict(source=str(target),name=n,mode=0o444,sha256=hashlib.sha256(data).hexdigest()))
    plan=out/"bootstrap-plan.json"
    data=encode(dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(PACKAGE),members=files))
    if not plan.exists():
        base["write"](plan,data)
    need(plan.read_bytes()==data,"changed bootstrap seal plan")
    return operator_sha,seal(plan)


def quote(path,sha,iid):
    q=fit["checked"]({"path":str(path),"sha256":sha})
    n=q["native"]
    expected=fit["inspect_price"](n,fit["checked"](n["fleet"])["retry9_auxiliary_commitments"],iid,time.time())
    need(expected==q["bootstrap"] and q["original_commands"]==fit["recipe"]()[1],
         "different complete bootstrap quote")
    audit=SLICE_DIR.parent
    need((audit/"cpu.max").read_text().strip()=="1200000 100000" and (audit/"memory.high").read_text().strip()==
         "21474836480" and (audit/"memory.max").read_text().strip()=="25769803776" and
         int((audit/"memory.current").read_text())+768*MIB <= int((audit/"memory.high").read_text()) and
         int((audit/"pids.current").read_text())+256 <= int((audit/"pids.max").read_text()),
         "parent audit slice cannot cover one supervisor + one child")
    output=run(["/usr/bin/systemctl","show","-p","InvocationID,ActiveState,MainPID","horizon-holding-export145-20261121-v1.service"])
    unit=dict(l.split("=",1) for l in output.splitlines())
    need(unit["InvocationID"]==iid and unit["ActiveState"]=="active" and int(unit["MainPID"])>0,
         "priced 145 verifier changed")


def capture(start, fleet_sha, iid):
    """Use the verifier's complete accepted-fleet chain and original two-member external-price window."""
    need(os.geteuid()==0 and sys.flags.isolated and __debug__, "root isolated price required")
    runtime=fit["RUNTIME"]
    tools=runtime/"incident-replay-fit-20261121-v1"
    current=tools/"tools-homefloor-145-missed-rejoin-v1"
    handoff=tools/"tools-homefloor-145-handoff-v4"
    def authenticated(directory, sha, member):
        seal=fit["checked"]({"path":str(directory/"deployment-seal-receipt.json"),"sha256":sha})
        need(seal["destination"]==str(directory) and seal["sealer_sha256"]==base["SEALER"],"wrong sealed reader")
        row,=[r for r in seal["members"] if r["name"]==member and r["mode"]=="0555"]
        prog=directory/member
        fit["pin"](prog,row["sha256"])
        return prog
    census=authenticated(current,"b2e28f51da8e428c106a23b3e5d73a6d92b1aca84043e82d1e662387d2c18b96","post-stop-fit")
    dispatcher=authenticated(handoff,"2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea","run-recovery")
    chain=runpy.run_path(str(dispatcher))["successors"]
    first={"path":str(start),"sha256":fleet_sha}
    cgroup=Path("/sys/fs/cgroup/system.slice/horizon-holding-export145-20261121-v1.service/cgroup.procs")
    end=time.monotonic()+150
    while time.monotonic()<end:
        current_ref=chain(first)[-1]
        if len(cgroup.read_text().split())!=2:
            time.sleep(1)
            continue
        cmd=[census,"145",current_ref["path"],current_ref["sha256"]]
        result=subprocess.run(cmd,capture_output=True,timeout=180)
        if result.returncode:
            error=result.stderr.decode()
            if (error.startswith("Traceback (most recent call last):") and str(census) in error and
                error.endswith("ValueError: foreign 145 descendants\n")):
                time.sleep(1)
                continue
            raise ValueError(error[-2048:])
        n=json.loads(result.stdout)
        need(n["fleet"]==current_ref and chain(first)[-1]==current_ref,"accepted fleet changed during quote")
        fleet=fit["checked"](current_ref)
        charge=fit["inspect_price"](n,fleet["retry9_auxiliary_commitments"],iid,time.time())
        _,commands=fit["recipe"]()
        out=BASE/("bootstrap-native-quote-"+str(time.time_ns())+".json")
        base["write"](out,encode(dict(native=n,bootstrap=charge,original_commands=commands)))
        return {"path":str(out),"sha256":base["file_sha"](out)}
    raise ValueError("could not complete the original external-price window")


def dispatch(commit, path, sha, iid):
    import stat
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,"root isolated dispatch required")
    source(commit)
    source_sha,pkg_sha=packages(commit)
    quote(path,sha,iid)
    state=BASE/"bootstrap-grant.json"
    need(not any(p.exists() for p in (state,IMAGE,WORK,SLICE_DIR)) and
         run(["/usr/bin/systemctl","show","-p","LoadState","--value",ROOT_UNIT])=="not-found",
         "one-shot scope already exists")
    for key in ("FragmentPath","DropInPaths"):
        need(not run(["/usr/bin/systemctl","show","-p",key,"--value",SLICE]),"existing slice definition")
    need(BASE.stat().st_dev==Path("/home/sol").stat().st_dev,"not HOME-backed")
    with IMAGE.open("xb") as f:
        os.fchmod(f.fileno(),0o600)
        os.posix_fallocate(f.fileno(),0,128*MIB)
        os.fsync(f.fileno())
    WORK.mkdir(mode=0o700)
    run(["/usr/sbin/mke2fs","-q","-t","ext4","-F","-m0","-E","nodiscard,lazy_itable_init=0,lazy_journal_init=0",IMAGE])
    run(["/usr/bin/mount","-o","loop,nodev,nosuid,nodiscard",IMAGE,WORK])
    os.chmod(WORK,0o700)
    (WORK/"tmp").mkdir(mode=0o700)
    st=IMAGE.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_blocks*512>=128*MIB,"image not physically funded")
    run(["/usr/bin/systemctl","set-property","--runtime",SLICE,"CPUQuota=100%","MemoryMax=2147483648",
         "MemorySwapMax=0","TasksMax=256"])
    props={"Type":"exec","User":"root","Group":"root","UMask":"0077","CPUQuota":"200%","MemoryMax":"256M",
           "MemorySwapMax":"0","TasksMax":"128","KillMode":"control-group","Restart":"no",
           "RuntimeMaxSec":"300","TimeoutStopSec":"10","PrivateNetwork":"yes","PrivateTmp":"yes",
           "ProtectSystem":"strict","ProtectHome":"read-only","NoNewPrivileges":"yes","LimitCORE":"0",
           "ReadWritePaths":str(WORK)+" /run/lock/horizon-epoch140-suffix-compiler.lock "+
              "/var/lib/jetstreamer/native16-compiler-suballocation-qualification-20261109-v1/native16-suballocation.lock",
           "StandardOutput":"null","StandardError":"journal"}
    now=int(time.time())
    g=dict(owner="/root",schema="horizon-native163-operator-bootstrap-grant-v1",created=now,deadline=now+300,
           image=dict(dev=st.st_dev,ino=st.st_ino,size=st.st_size),unit=ROOT_UNIT,slice=SLICE,
           live_145_iid=iid,commit=commit,source_sha256=source_sha,package_sha256=pkg_sha,
           price=dict(path=str(path),sha256=sha),source_qualification_only=True,resource_credit_bytes=0,
           consumer_phases_authorized=False,restore_authorized=False)
    base["mounted"](g)
    quote(path,sha,iid)
    base["write"](state,encode(g))
    args=["/usr/bin/systemd-run","--no-block","--unit="+ROOT_UNIT,"--slice="+SLICE]
    for k,v in props.items():
        args.extend(("-p",k+"="+v))
    args+=["--","/usr/bin/python3","-IB",str(PACKAGE/"bootstrap.py"),"root",str(state),base["file_sha"](state)]
    base["write"](BASE/"bootstrap-dispatch-intent.json",encode(args))
    subprocess.run(args,check=True,timeout=25)
    print(state,base["file_sha"](state))


if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="prepare":
        print(json.dumps(packages(sys.argv[2])))
    elif len(sys.argv)==5 and sys.argv[1]=="quote":
        print(json.dumps(capture(Path(sys.argv[2]),sys.argv[3],sys.argv[4])))
    elif len(sys.argv)==6 and sys.argv[1]=="dispatch":
        dispatch(sys.argv[2],Path(sys.argv[3]),sys.argv[4],sys.argv[5])
    else:
        raise SystemExit("expected prepare COMMIT, quote FLEET SHA LIVE_145_IID or dispatch COMMIT QUOTE SHA LIVE_145_IID")
