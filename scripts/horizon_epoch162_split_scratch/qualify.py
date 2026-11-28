"""One-off fixture only. Exercise the stock epoch 162 entry with isolated, bounded test media."""
import argparse
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

PRIVATE = Path("/home/sol/.jetstreamer-private")
ORIGINAL = PRIVATE / "epoch162-local-capped-20261127.6qaa2Qgr"
STOCK = ORIGINAL / "native-1795816667784782329"
RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
SOURCE = Path(__file__).resolve().parent
M = 1 << 20
G = 1 << 30


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def ref(path):
    with path.open("rb") as stream:
        return dict(path=str(path), sha256=hashlib.file_digest(stream, "sha256").hexdigest())


def save(path, data):
    with path.open("x") as out:
        json.dump(data, out, indent=2, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fchmod(out.fileno(), 0o444)
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)


def identity(path):
    st = path.stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_ctime_ns, st.st_mtime_ns]


def synthetic_snapshot(target):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [("accounts",None), ("snapshots",None), ("snapshots/69983760",None),
                           ("snapshots/69983760/69983760", b"\0"*8), ("version", b"1.2.0")]:
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE if data is None else tarfile.REGTYPE
            entry.mode = 0o700 if data is None else 0o600
            entry.size = 0 if data is None else len(data)
            tar.addfile(entry, None if data is None else io.BytesIO(data))
    target.write_bytes(subprocess.check_output(["zstd","-q","-c"],input=raw.getvalue()))
    target.chmod(0o444)


def stage(run, phase, stock, image_bytes, scratch_bytes):
    directory=run/phase
    directory.mkdir(mode=0o755)
    plan=directory/"fixture.json"; view=directory/"tree"; seed=directory/"seed"
    inputs=directory/"inputs"; evidence=directory/"evidence"
    for item in [view, seed, inputs, evidence]:
        item.mkdir(mode=0o755)
    os.chown(evidence,1001,1003)
    for name in ["ledger", "private","scratch"]:
        (seed/name).mkdir(mode=0o700)
        os.chown(seed/name,1001,1003)
    original_tree=STOCK/"work"; original_inputs=STOCK/"inputs"
    binds=[]; paths={}
    if phase in ("native36", "native32"):
        for row in stock["bindings"]:
            src=Path(row["source"]); old=Path(row["view"])
            require(identity(src)==row["identity"], "staged source identity drifted " + str(src))
            if old.is_relative_to(original_tree):
                rel=old.relative_to(original_tree); dst=view/rel
                placeholder=seed/rel;placeholder.parent.mkdir(parents=True,exist_ok=True)
                placeholder.touch(mode=0o644)
            elif old.is_relative_to(original_inputs):
                dst=inputs/old.name; dst.touch(mode=0o644)
            else:
                require(old.parent==Path("/run/horizon-car-slot-ranges-161-163-epoch162"), "foreign range view")
                dst=old
            binds.append(dict(row,view=str(dst)))
            paths[str(old)]=str(dst)
    image=directory/"mutable.ext4"
    with image.open("xb") as out:out.truncate(image_bytes)
    subprocess.run(["/usr/sbin/mkfs.ext4","-q","-F","-b","4096","-m","0","-N","32768" if phase in ("native36", "native32") else "1024",
                    "-O","^has_journal","-E","root_owner=1001:1003,lazy_itable_init=1,nodiscard",
                    "-d",str(seed),str(image)],check=True)
    require(image.stat().st_size==image_bytes and image.stat().st_blocks*512<32*M and
            image.stat().st_dev==PRIVATE.stat().st_dev,"image funding or filesystem differs")
    cfg=dict(token=run.name+phase,view=str(view),backing_image=str(image),image_bytes=image_bytes,scratch_bytes=scratch_bytes,
             trace=str(evidence/"native-syscalls.log"),bindings=binds)
    environment={}
    if phase in ("native36", "native32"):
        actual=inputs/stock["snapshot"]; mocked=directory/"mock"/stock["snapshot"]
        mocked.parent.mkdir(mode=0o755);synthetic_snapshot(mocked)
        argv=[paths.get(a,a.replace(str(original_tree),str(view)).replace(str(original_inputs),str(inputs))) for a in stock["argv"]]
        argv=[("--snapshot-archive="+str(mocked)) if a.startswith("--snapshot-archive=") else a for a in argv]
        cfg.update(argv=argv,real_bootstrap=str(actual),mock_bootstrap=str(mocked),mock_digest=ref(mocked))
        old=json.loads((STOCK/"STARTUP_COMMAND.json").read_bytes())["command"]
        for item in old:
            if item.startswith("--setenv="):
                k,v=item.removeprefix("--setenv=").split("=",1)
                environment[k]=v.replace(str(original_tree),str(view)).replace(str(original_inputs),str(inputs))
        environment.update(RAYON_NUM_THREADS="2",SOLANA_RAYON_THREADS="2")
    save(plan,cfg)
    return directory,view,image,plan,environment


def exercise(phase,directory,view,image,plan,environment):
    cfg=json.loads(plan.read_bytes());iidtag=str(time.time_ns());unit=f"horizon-162-split-fixture-{phase}-{iidtag}.service"
    props=["User=sol","Group=horizon","ProtectSystem=strict","ProtectHome=read-only","PrivateTmp=yes",
           "PrivateDevices=yes","PrivateNetwork=yes","PrivateMounts=yes","NoNewPrivileges=yes",
           "CapabilityBoundingSet=","MemoryMax=512M","MemorySwapMax=0","CPUQuota=25%",
           "TasksMax=128","LimitCORE=0","LimitFSIZE=33554432","RuntimeMaxSec=120","TimeoutStopSec=5",
           "KillMode=control-group","UMask=0077"]
    opts="ro,noload,nosuid,nodev" if phase=="readback" else "rw,nosuid,nodev"
    props.append(f"MountImages={image}:{view}:{opts}")
    if phase!="readback":
        inode_cap=1<<20 if phase in ("native36", "native32") else 1024
        props.append(f"TemporaryFileSystem={view}/scratch:rw,noswap,size={cfg['scratch_bytes']},nr_inodes={inode_cap},uid=1001,gid=1003,mode=0700")
        props.append("ReadWritePaths="+str(directory/"evidence"))
    if phase in ("native36", "native32"):
        props.append("BindReadOnlyPaths="+" ".join(row["source"]+":"+row["view"] for row in cfg["bindings"]))
    cmd=["/usr/bin/systemd-run","--quiet","--collect","--wait","--pipe","--service-type=exec","--unit="+unit]
    cmd+=["--property="+p for p in props]+["--setenv="+k+"="+v for k,v in environment.items()]
    cmd+=["--","/usr/bin/python3","-IB",str(SOURCE/"inside.py"),phase,str(plan)]
    request=save(directory/(phase+"-request.json"),dict(unit=unit,command=cmd,plan=ref(plan),inner=ref(SOURCE/"inside.py")))
    got=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=140)
    log=directory/(phase+".log");log.write_text(got.stdout);log.chmod(0o444)
    if got.returncode:
        raise RuntimeError(f"{unit} exit={got.returncode}: {got.stdout[-1250:]} (log {log})")
    result=json.loads(next(x for x in reversed(got.stdout.splitlines()) if x.startswith('{"phase"')))
    ii=result["iid"]
    journal=subprocess.check_output(["journalctl","-b","-q","--no-pager","-o","json","_PID=1","_UID=0","UNIT="+unit,"INVOCATION_ID="+ii],text=True)
    events=[json.loads(s)for s in journal.splitlines()]
    require(any(x.get("MESSAGE_ID")=="7ad2d189f7e94e70a38c781354912448" for x in events),"missing clean PID1 exit")
    summary=[{k:x[k]for k in ("MESSAGE_ID","MESSAGE","__REALTIME_TIMESTAMP","__CURSOR","MEMORY_PEAK","CPU_USAGE_NSEC") if k in x}for x in events]
    return save(directory/(phase+"-result.json"),dict(unit=unit,invocation=ii,entry=request,log=ref(log),
                native_result=result,pid1_terminal=summary,image_allocated_after=image.stat().st_blocks*512))


def qualify(root,quote):
    require(os.geteuid()==0 and root.resolve()==root and root.parent==PRIVATE and root.name.startswith("epoch162-split-scratch-"),
            "fixture requires its own private root")
    fit=json.loads(quote.read_bytes()); live=fit["remaining"]
    require(fit["utc"].startswith("2026-11-") and fit["resource_credit_bytes"]==0 and not fit["runtime_launch"]
            and live["home"]>8*G+64*M and live["ram"]>512*M and fit["bookings"]["rooms"]["build_ram"]==2*G,
            "no bounded fixture room or changed profile")
    stamp=str(time.time_ns()); run=root/("test-"+stamp); run.mkdir(mode=0o755)
    native_old=json.loads((STOCK/"fixture.json").read_bytes())
    acceptance=json.loads((STOCK/"STARTUP_ACCEPTANCE.json").read_bytes())
    require(acceptance["scope"]==ref(STOCK/"fixture.json") and native_old["worker_sha256"]=="79179ca07a537c0f63f7f5012e24b0f66092d7853852ea50d67cb3f03b7ab691","source changed")
    print(run,flush=True)
    results={}
    with open("/run/lock/horizon-epoch140-suffix-compiler.lock","rb") as serial:
        fcntl.flock(serial,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for phase,home,scratch in [("native36",8*G,36*G),("native32",8*G,32*G),("pressure",16*M,2*M)]:
            directory,view,image,plan,environment=stage(run,phase,native_old,home,scratch)
            results[phase]=exercise(phase,directory,view,image,plan,environment)
            results[phase+"_readback"]=exercise("readback",directory,view,image,plan,{})
        checks={}
        for label,cmd in {"terminal":["/usr/bin/python3","-IB",str(ORIGINAL/"check-terminal.py"),"--fixture"],
                          "stock_prefix":["/usr/bin/python3","-IB",str(ORIGINAL/"stock-prefix.py")]}.items():
            proc=subprocess.run(cmd,capture_output=True,check=True,timeout=60)
            value=json.loads(proc.stdout)
            if label=="terminal": require(value["positive"]==1 and value["negative"]==7 and not value["production_journal"],"terminal comparator changed")
            else: require(value["candidate"] is None and value["stock"]["first"]==69984000 and value["stock"]["last"]==69984127
                          and not value["accepted_private_output"],"stock reference changed")
            checks[label]=save(run/(label+".json"),value)
    need_home=8*G+64*M
    alternatives = {str(s):dict(scratch_bytes=s*G,worker_bytes=26*G,guard_bytes=G,combined_ram_bytes=(s+27)*G,
                                  home_after=live["home"]-need_home,ram_after=live["ram"]-(s+27)*G) for s in [36,32]}
    out=save(run/"ACCEPTED.json",dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        native_fixture=True,production_grant=False,real_epoch_run=False,price=ref(quote),existing_native_162=ref(STOCK/"STARTUP_ACCEPTANCE.json"),
        test_source=ref(SOURCE/"qualify.py"),native_probe=ref(SOURCE/"inside.py"),runs=results,comparators=checks,
        home_bytes=need_home,priced_profiles=alternatives,raw_room=live,
        immutable_inputs_are_read_only=True,archive_publication_authorized=False,
        limitations=["The empty fixture Bank reaches native account-directory creation and fails decode. It cannot establish real-interval RAM, tmpfs, output size, byte equality or terminal Bank outcome.",
                     "Stock-vs-capped comparison still requires the first native output bucket, and the terminal comparison still requires the actual invocation-bound Bank witness.",
                     "The proposed production image is writable only in its mounting unit. The HOME image has an 8 GiB hard size and control has a separate 64 MiB allowance; price guard observations and retain the image through readback."]))
    print(json.dumps(out),flush=True)


if __name__=="__main__":
    args=argparse.ArgumentParser()
    args.add_argument("fixture_root",type=Path);args.add_argument("issued_price",type=Path)
    a=args.parse_args();qualify(a.fixture_root,a.issued_price)
