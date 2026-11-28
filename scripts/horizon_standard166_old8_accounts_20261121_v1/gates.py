"""Bind the stopped standard retry8 AppendVecs and the live independent epoch 166 worker."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
TOOLS = R/"incident-replay-fit-20261121-v1/tools-v3"
SURVEY = R/"epoch170-retry10-recovery-20261121-v1/OLD_STANDARD166_SCOPE_A.json"
LAUNCH = Path("/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166")
PACKAGE = Path("/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1")
UNIT = "horizon-qualify-166-replacement-local3retry8-20261110-v1.service"
OLD = "4f09db5f45074244a45b06aeef932d1d"
INDEPENDENT = Path("/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1")
NODE = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
WORKER = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def staged_readers(target, partial):
    directories=("/etc/systemd/system","/run/systemd/transient","/run/systemd/system","/run/systemd/generator",
                 "/run/systemd/generator.early","/run/systemd/generator.late","/usr/lib/systemd/system")
    own=Path("/proc/self/cgroup").read_text().strip().split("/")[-1]
    run=partial.parent.parent
    needles=[os.fsencode(v) for v in (str(target),target.parent.name,target.parents[1].name,run.name)]
    for directory in directories:
        for parent,_,files in os.walk(directory,followlinks=False):
            for name in files:
                path=Path(parent)/name
                if path.is_symlink() or not name.endswith((".service",".path",".timer",".socket",".conf",".mount",".target")):
                    continue
                z=path.lstat()
                require(stat.S_ISREG(z.st_mode) and z.st_size<32<<20,"unexpected scheduler file")
                body=path.read_bytes()
                if not any(n in body for n in needles):continue
                if directory=="/run/systemd/transient" and name==own and own.startswith("horizon-oldstandard166-"):
                    # Only the narrow check/execute package namespace may project this one directory.
                    text=body.decode().splitlines()
                    matching=[line for line in text if any(os.fsdecode(n) in line for n in needles)]
                    require(len(matching)==1 and matching[0] in ("ReadOnlyPaths="+str(target),"ReadWritePaths="+str(target)),
                            "foreign self reference")
                    continue
                raise ValueError("historical scratch scheduler reference: "+str(path))

def gates():
    require(os.getuid()==0 and sys.flags.isolated and __debug__, "isolated native root checker required")
    seal=TOOLS/"deployment-seal-receipt.json"
    require(seal.resolve()==seal and seal.stat().st_uid==0 and
            digest(seal)=="a0badf9e7a9028139c281b55dead5965b540aae49b7d42869a886b264eabfc8b","changed incident tools")
    for m in json.loads(seal.read_bytes())["members"]:
        p=TOOLS/m["name"]
        require(p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode&0o222 and digest(p)==m["sha256"],"changed protected helper")
    m=runpy.run_path(str(TOOLS/"post-stop-fit"))
    s=m["s"]
    report,rr=s.read(SURVEY,"ac7a2fb704f60338e213c143d206386086a8ac3fd01644a2a42b9d50cffe8110")
    row,=[q for q in report["generations"] if q["attempt"]==8]
    t=Path(row["scope"]);rt=t.stat()
    require(t.resolve(strict=True)==t and t.name=="accounts-state" and t.parent.name=="jetstreamer-historical-v1.5.6-ARRvsn" and
            (rt.st_dev,rt.st_ino,rt.st_uid,rt.st_gid,rt.st_blocks)==(64512,108068870,1001,1003,row["scope_root_blocks"])
            and row["entries"]==398554 and row["physical_bytes"]==59244568576,"foreign old8 accounts tree")
    inspection=m["bound"](row["inspection"]);original=inspection["stopped_producer"]
    require(original==row["original"] and original["invocation_id"]==OLD and original["pid"]==1746683,"different original retry8")
    intent=m["bound"](original["intent"]);done=m["bound"](original["completion"]);terminal=done["terminal"]
    require(intent["producer_invocation_id"]==done["producer_invocation_id"]==OLD and intent["plan_sha256"]==done["plan_sha256"] and
            intent["reason"]=="DATA-fulfillment-observation-failed" and not done["scratch_deleted"] and
            terminal["pid"]==0 and terminal["active"]=="inactive" and terminal["cgroup"]=="/system.slice/"+UNIT,"old8 stop changed")
    for name in (UNIT,"horizon-guard-replacement-166-local3retry8-20261110-v1.service","horizon-guard-replacement-166-local3retry8-20261110-v1.timer"):
        v=s.show(name)
        require(v["ActiveState"]=="inactive" and not v["Job"] and not (Path("/sys/fs/cgroup/system.slice")/name).exists(),"old8 owner returned")
    for q in row["retained"]:
        path=Path(q["path"]);z=path.lstat()
        require(path.resolve()==path and z.st_dev==64512 and stat.S_ISREG(z.st_mode) and z.st_uid==1001 and z.st_gid==1003 and
                z.st_nlink==1 and (z.st_ino,z.st_size,z.st_blocks,z.st_mtime_ns,z.st_ctime_ns)==
                tuple(q[k] for k in ("inode","length","blocks512","mtime_ns","ctime_ns")) and not path.is_relative_to(t),"retained old8 evidence changed")
    partial,bootstrap,old_worker,bank=[Path(q["path"]) for q in row["retained"]]
    run=partial.parent.parent
    require(str(partial)==inspection["source"] and partial.stat().st_size==55516564111 and run.name=="run-1746683-1795053006864315025" and
            t.is_relative_to(run/"scratch") and bank.name=="71711708" and bootstrap.name.startswith("snapshot-71711708-") and
            bootstrap.stat().st_size==1968014870 and digest(old_worker)==WORKER,"old8 origin or worker changed")
    staged_readers(t,partial)
    argv,ar=s.read(LAUNCH/"ORIGINAL_PRODUCER_ARGV.json","53459e75c16c51ae6a7c336011a44965d7c5006f3f1b54dd3907163e7f85d84f")
    ad,adr=s.read(LAUNCH/"ACTUAL_REPLACEMENT_ADMISSION.json","3cb6ab13fab607414111c2e027ff36b9716b1050de008e631e5475df5d857273")
    guard,gr=s.read(LAUNCH/"ACTUAL_GUARD_PROTECTION.json","c50f120993c44bd899a81deb260dd1c2e68505020457af793611525534061918")
    require(ad["producer_unit"]==guard["producer_unit"]==UNIT and ad["producer_invocation_id"]==guard["producer_invocation_id"]==OLD and
            guard["admission"]==adr and "--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true" in argv and "--setenv=JETSTREAMER_LOAD_FROM_DIR=0" in argv and
            argv[-1].endswith("/"+bootstrap.name) and str(PACKAGE/"jetstreamer-node") in argv and str(t) not in str(argv),"old8 replay origin changed")
    pkg,ps=s.read(PACKAGE/"deployment-seal-receipt.json","59f3e31877df7f267859d9385135214b7c2c17c66b52e117c1cd88874761dbcc")
    require(pkg["destination"]==str(PACKAGE) and
            {(x["name"],x["sha256"]) for x in pkg["members"]}>={("jetstreamer-node",NODE),("jetstreamer-historical-worker-v1-5-6",WORKER)},"different original package")
    source=Path("/usr/local/lib/jetstreamer/horizon-standard166-scratch-retire-source-20261110-v1/source-review.md")
    require(digest(source)=="342a7673ccefc6a89413b2122a17b4542ce4a7aae9f1a55240999b395ddf256b","earlier qualified scratch source review changed")
    prior,_=s.read(Path("/var/lib/jetstreamer/standard166-scratch-retirement-qualification-20261110-v1/ROOT_ACTUAL166_SCRATCH_CONTENTS_RETIREMENT_COMPLETE.json"),
                   "fbe2cac3158bc9a00a578357523c61a267c22f971d3f4da09dac5614415d94d6")
    require(prior["all_inputs_state_and_partial_preserved"] and prior["scratch_root_inode_preserved"],"original standard166 scratch semantics changed")
    fresh=m["native_actor"](166,170,INDEPENDENT,m["stable_root"](166),m["proof_stops"]()["166"])
    require(fresh and len(fresh["processes"])==2 and fresh["admission"] and not t.is_relative_to(INDEPENDENT) and
            not INDEPENDENT.is_relative_to(t),"independent166 not executing separately")
    first,wr=s.read(R/"epoch166-independent-cold-recovery-20261121-v1/FIRST_PROTECTED_WORKER.json","19ed8279aaf1e85bdadae6974d2d1c6f1d1c019a122d7bad5d26259c9d3eb4aa")
    require(first["producer_invocation_id"]==fresh["producer_invocation_id"] and first["worker_sha256"]==WORKER and
            first["worker_pid"]==fresh["processes"][1][0] and first["admission"]==fresh["admission"],"wrong independent166 worker")
    w,wref=s.read(R/"epoch170-retry10-guard384-20261121-v1/NATIVE_WITNESS.json","0527ef33a3ab247462e03c44d515cda2b1273e2f99b5d69f0cb9a73f6b93eba5")
    qs=w["allocation"]["first"];require(len(qs)==12 and qs==w["allocation"]["second"],"wrong DATA roster")
    for q in qs:
        path=Path(q["path"]);st=path.stat()
        require(not path.is_relative_to(t) and not t.is_relative_to(path) and (st.st_dev,st.st_ino)==(q["dev"],q["ino"]),"protected DATA intersects old8")
    return dict(scope=dict(target=str(t),inode=rt.st_ino,expected_bytes=row["physical_bytes"]),survey=rr,old=original,argv=ar,original_admission=adr,
                original_guard=gr,package=ps,independent_admission=fresh["admission"],independent_worker=wr,DATA_witness=wref,retained=row["retained"])

if __name__=="__main__":print(json.dumps(gates(),sort_keys=True))
