"""Derive the pinned retry gate and terminal watcher, and qualify their service namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c

HERE = Path(__file__).resolve().parent
OLD = c.OLD_CONTROL / "issued-split-v1"
DEPLOY = c.CONTROL / "operator-v1"
TERMINAL = "horizon-169-hourly-retry-terminal-20261128-v1.service"
MANIFEST = "epoch-hashes-169-focused.txt"
OLD_STOP = "horizon-169-hourly-terminal-20261123-v1.service"
CURRENT = c.PRIVATE / "epoch169-current-local-20261127.PVtVmVGN/CURRENT_INPUTS.json"
PROJECTS = ("contract.py","namespace.py","scratch_mount.py","gate.py")


def once(source, old, new):
    c.need(source.count(old)==1, "changed pinned template: " + old)
    return source.replace(old,new)


def file_text(path, digest, *, sealed=True):
    _, data = c.stable(path, expected=digest, sealed=sealed, keep_bytes=True)
    return data.decode()


def gate():
    source = file_text(OLD/"hourly_gate.py","a1f9b7e876dcd8ed931f10bbc7b24ec6c5f4a5c6093fc4a84db68a20b215a01a")
    for old, new in (
        (c.OLD_UNIT,c.UNIT), ("epoch169-hourly-private-postguard-release-v1","epoch169-hourly-retry-postguard-release-v1"),
        ("== 3_000_000","== 2_000_000"), ('["300000","100000"]','["200000","100000"]'),
        ('BIND/"allow.json"',f'Path("{c.BARRIER}/allow.json")'),
        ('BIND / "scratch_mount.py"',f'Path("{c.BARRIER}/scratch_mount.py")'),
        ('SOLANA_RAYON_THREADS="3",RAYON_NUM_THREADS="3",JETSTREAMER_HISTORICAL_POH_THREADS="3"',
         'SOLANA_RAYON_THREADS="2",RAYON_NUM_THREADS="2",JETSTREAMER_HISTORICAL_POH_THREADS="2"'),
        ('os.chdir(DEST)', f'''mounts = runpy.run_path("{c.BARRIER}/namespace.py")
    need(mounts["inspect"](os.getpid()) == grant["namespace"], "held retry projections changed")
    os.chdir(DEST)'''),
    ):
        source = once(source,old,new)
    c.need(source.count("68*G")==2 and source.count("64*G")==1, "changed predecessor memory contract")
    return source.replace("68*G","56*G").replace("64*G","52*G")


def watcher():
    source = file_text(OLD/"watch.py","4006f99899453653537a0840e1b8859dfe0f5ca7086dfbcacaeb4b32718c76de")
    for old,new in ((c.OLD_UNIT,c.UNIT), (str(c.OLD_CONTROL),str(c.CONTROL)), (str(c.OLD),str(c.RETRY)),
                    ('+str(MANIFEST)',f'+str(Path("{c.OLD}/v158/{c.BASE_NAME}.segment.json"))')):
        source=once(source,old,new)
    return source


def actor():
    original=file_text(OLD/"actor.py","1e3ed3a6930853a5df4fb62bb7275ba620b8a4856bd0c95bcaf6e32fcd1c0b4c")
    source=original.split("\ndef public_workers(",1)[0]
    old_closure='''need(fleet["focused169_terminal"]==src["previous_terminal"]==dict(
             path="/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-terminal-20261121-v1/TERMINAL.json",
             sha256="218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"),"unjoined prior closure")'''
    new_closure=f'''need(src["previous_terminal"]==dict(path="{c.OLD_CONTROL}/results/TERMINAL.json",
             sha256="07e7f475687fecb9cb5fbd154951d84443e4a134c8889f0ce1d8857b884aef3e")
             and pinned(src["previous_terminal"])["invocation_id"]==src["previous_producer_iid"],
             "different retained hourly closure")'''
    for old,new in (
        (str(c.OLD_CONTROL),str(c.CONTROL)),(str(c.OLD),str(c.RETRY)),(c.OLD_UNIT,c.UNIT),
        ("horizon-guard-169-focused-hourly-20261123-v1.timer","horizon-guard-169-hourly-retry-20261128-v1.timer"),
        ("0dfa0d36fbc246c28443a1c90a82c9cb",c.OLD_IID),
        ("epoch169-hourly-tmpfs-first-guard-intent-v1","epoch169-hourly-retry-first-guard-v1"),
        ("64 << 20, 8 * G","64 << 20, 4 * G"),('src["actor_cpu_micros"]==3_000_000','src["actor_cpu_micros"]==2_000_000'),
        ('["300000","100000"]','["200000","100000"]'),('=="3s"','=="2s"'),
        ('b"/run/horizon-169-hourly/hourly_gate.py"',f'b"{c.BARRIER}/gate.py"'),
        ('name.is_relative_to(TREE/"v158/scratch")',f'name.is_relative_to(Path("{c.OLD}/v158/scratch"))'),
        (old_closure,new_closure)
    ):
        source=once(source,old,new)
    c.need(source.count("68*G")==3 and source.count("64*G")==1, "changed native actor caps")
    return source.replace("68*G","56*G").replace("64*G","52*G")


def service():
    source=file_text(Path("/run/systemd/system")/c.OLD_UNIT,
                     "9b44abda61722dfbc23652910a91da70fa2c7b9ce672984d958217ab83a1ed68",sealed=False)
    c.need(source.count(OLD_STOP)==2, "changed terminal triggers")
    source=source.replace(OLD_STOP,TERMINAL)
    pairs=" ".join(f"{DEPLOY/name}:{c.BARRIER/name}" for name in PROJECTS)
    for old,new in (
        ("CPUQuota=300%","CPUQuota=200%"),("MemoryHigh=68719476736",f"MemoryHigh={52*c.G}"),
        ("MemoryMax=73014444032",f"MemoryMax={c.RAM}"),("Guarded private epoch 169 hourly Bank reproduction",
                                                     "Private retry of epoch 169 from hourly Bank 73238440"),
        (f" {OLD}/hourly_gate.py:{c.NODE_BIND}/hourly_gate.py {OLD}/scratch_mount.py:{c.NODE_BIND}/scratch_mount.py",
         f" {pairs} {c.RETRY}/v158/{MANIFEST}:{c.OLD}/v158/{MANIFEST}\nBindPaths={c.RETRY}/v158:{c.OLD}/v158 {c.RETRY}/hourly-run:{c.OLD}/hourly-run"),
        (f"ExecStart=/usr/bin/python3 -IB {c.NODE_BIND}/hourly_gate.py",f"ExecStart=/usr/bin/python3 -IB {c.BARRIER}/gate.py"),
    ):
        source=once(source,old,new)
    c.need(source.count(f"append:{c.OLD}/hourly-run/producer.log")==2, "changed host log mapping")
    return source.replace(f"append:{c.OLD}/hourly-run/producer.log",f"append:{c.RETRY}/hourly-run/producer.log")


def static_files(staging):
    old_watcher=file_text(Path("/run/systemd/system")/OLD_STOP,
                          "bef402d0174cefad3a5477b9f31a9f6dbd3735dcea5e8fb77880b096790f4818",sealed=False)
    old_watcher=once(old_watcher,str(c.OLD_CONTROL/"results"),str(c.CONTROL/"results"))
    old_watcher=once(old_watcher,str(c.OLD_CONTROL/"sealed/watch.py"),str(DEPLOY/"watch.py"))
    contents={"gate.py":gate(),"watch.py":watcher(),"actor.py":actor(),c.UNIT:service(),TERMINAL:old_watcher,
              "scratch_mount.py":file_text(OLD/"scratch_mount.py","84d0e9595c355e8a75e73d63f2d9153db9164ef2e74b8508ef4d3c161a0a2fdd")}
    for name in ("contract.py","namespace.py","custody.py","quote.py","observe.py","prepare.py"):
        contents[name]=(HERE/name).read_text()
    members=[]
    for name,data in contents.items():
        if name.endswith(".py"):
            compile(data,name,"exec")
        path=staging/name
        with path.open("x") as out:
            out.write(data)
        members.append(dict(name=name,source=str(path),mode=0o444,sha256=hashlib.sha256(data.encode()).hexdigest()))
    return members


def layout():
    current,ref=c.read(CURRENT,"efa0ebcceb5792c0a2be1c9f4db449e2c753ce06a907501787452712ef87afdb")
    def directory(path,uid,gid,mode):
        if not path.exists():
            path.mkdir(mode=mode)
            os.chown(path,uid,gid)
            path.chmod(mode)
        st=path.lstat()
        c.need(path.resolve()==path and stat.S_ISDIR(st.st_mode) and
               (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(uid,gid,mode), "foreign directory " + str(path))
    directory(c.RETRY,0,0,0o755)
    for suffix in ("v158","v158/compact-indexes","v158/compact-indexes/168","v158/compact-indexes/169",
                   "v158/scratch","hourly-run","hourly-run/tmp","hourly-run/private"):
        directory(c.RETRY/suffix,1001,1003,0o700)
    for path in (c.CONTROL/"results",c.RETRY/"hourly-guard-receipts"):
        directory(path,0,0,0o700)
    directory(c.BARRIER,0,0,0o755)
    checkpoint=c.RETRY/"v158"/MANIFEST
    raw=current["output"]["source_hash_manifest"].encode()
    if not checkpoint.exists():
        fd=os.open(checkpoint, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        with os.fdopen(fd,"wb") as out:
            out.write(raw)
            out.flush()
            os.fchmod(out.fileno(),0o444)
            os.fsync(out.fileno())
    c.stable(checkpoint,expected=current["output"]["source_hash_manifest_sha256"],sealed=True)
    genesis=c.RETRY/"v158/genesis.tar.bz2"
    if not genesis.exists():
        genesis.touch(mode=0o444, exist_ok=False)
    c.need(genesis.is_file() and genesis.stat().st_size==0 and genesis.stat().st_uid==0,
           "foreign genesis mountpoint")
    for path in (c.RETRY/"v158/scratch",c.RETRY/"hourly-run/tmp",c.RETRY/"hourly-run/private"):
        c.need(not any(path.iterdir()),"occupied retry path: "+str(path))
    for path in (c.RETRY/"v158"/c.BASE_NAME,c.RETRY/"v158"/(c.BASE_NAME+".segment.json"),c.BARRIER/"allow.json"):
        c.need(not os.path.lexists(path), "retry already occupied: "+str(path))
    return ref


def fixture(deployment):
    ref=layout()
    properties=service().partition("[Service]\n")[2].splitlines()
    skip={"Type","StandardOutput","StandardError","ExecStart"}
    args=["/usr/bin/systemd-run","--quiet","--wait","--collect","--service-type=exec",
          f"--unit=horizon-169-retry-namespace-fixture-{time.time_ns()}"]
    for row in properties:
        if row and row.split("=",1)[0] not in skip:
            args.append("--property="+row.replace(str(DEPLOY)+"/",str(deployment)+"/"))
    log=c.CONTROL/f"NAMESPACE-{time.time_ns()}.log"
    args.extend([f"--property=StandardOutput=append:{log}",f"--property=StandardError=append:{log}",
                 "/usr/bin/python3","-IB",str(c.BARRIER/"namespace.py")])
    process=subprocess.run(args, capture_output=True, text=True, timeout=35)
    c.need(process.returncode==0, f"fixture failed with {process.returncode}: {log} {process.stderr}")
    _,data=c.stable(log,keep_bytes=True)
    proof=json.loads(data)
    c.need(proof["schema"]=="horizon-169-retry-native-namespace-v1" and proof["uid"]==1001
           and not proof["useful_worker_launched"], "foreign namespace result")
    return c.recorded(c.CONTROL/f"NAMESPACE_{time.time_ns()}.json",
                      dict(properties=args, readback=proof, current_inputs=ref, admission=False))


if __name__ == "__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("plan","fixture"))
    cli.add_argument("staging",type=Path)
    args=cli.parse_args()
    c.need(os.geteuid()==0 and args.staging.resolve(strict=True)==args.staging
           and args.staging.stat().st_dev==c.HOME.stat().st_dev, "use a private HOME stage")
    if args.action=="plan":
        plan=dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(DEPLOY),
                  members=static_files(args.staging))
        result=c.recorded(c.CONTROL/f"PLAN_{time.time_ns()}.json",plan)
    else:
        result=fixture(args.staging)
    print(json.dumps(result))
