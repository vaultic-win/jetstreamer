"""Execute the five original operator QA commands under one already-booked aggregate CPU."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import runpy
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
fit = runpy.run_path(str(HERE / "bootstrap_fit.py"))
need, checked, pin = fit["need"], fit["checked"], fit["pin"]
MIB = 1 << 20
BASE = fit["RUNTIME"] / "epoch163-native48-inodes-20261123-v1"
SOURCE = BASE / "operator-source"
PACKAGE = BASE / "bootstrap-tools"
WORK = BASE / "bootstrap-work"
IMAGE = BASE / "bootstrap.ext4"
ORIGINAL = Path("/var/lib/jetstreamer/native163-consumer15-operator-source-qa-20261112-v1/work")
OLD_SOURCE = "/usr/local/lib/jetstreamer/horizon-native163-consumer15-operator-source-20261112-v3/main.rs"
ROOT_UNIT = fit["FAMILY"] + "-root.service"
TMP = WORK / "tmp"
STAGES = fit["LABELS"]
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def unit(label):
    need(label in STAGES, "unknown source QA command")
    return fit["FAMILY"] + "-" + label + ".service"


def file_sha(p):
    with p.open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def package(directory, digest, expected):
    seal = checked({"path": str(directory/"deployment-seal-receipt.json"), "sha256": digest})
    need(seal["destination"] == str(directory) and seal["sealer_sha256"] == SEALER and
         {m["name"] for m in seal["members"]} == set(expected) and len(seal["members"]) == len(expected),
         "different normally sealed source package")
    for m in seal["members"]:
        pin(directory/m["name"], m["sha256"])
        need(stat.S_IMODE((directory/m["name"]).stat().st_mode) == int(m["mode"],8) == 0o444,
             "different sealed source mode")


def mounted(grant):
    meta = IMAGE.lstat()
    dev = WORK.stat().st_dev
    back = Path("/sys/dev/block") / f"{os.major(dev)}:{os.minor(dev)}" / "loop/backing_file"
    need(Path(back.read_text().strip()).stat() == meta and meta.st_dev == Path("/home/sol").stat().st_dev and
         (meta.st_dev,meta.st_ino,meta.st_size) == tuple(grant["image"][k] for k in ("dev","ino","size")) and
         stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == meta.st_gid == 0 and
         stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size == 128*MIB and meta.st_blocks*512 >= meta.st_size and
         WORK.is_mount() and stat.S_IMODE(WORK.stat().st_mode) == 0o700, "unfunded bootstrap image")


def original(recipe, label):
    a = recipe["exact5_source_QA_recipes"][label]["candidate_argv"]
    program = str(ORIGINAL/"build-tests") if label == "ordinary-tests" else recipe[
        "compiler" if label in ("production","build-tests") else "clippy"]["path"]
    i = a.index(program)
    return list(a[:i]), list(a[i:])


def child_argv(recipe, label, grant_ref):
    props, _ = original(recipe,label)
    for i,v in enumerate(props):
        if v.startswith("--unit="):
            props[i] = "--unit=" + unit(label)
        elif v.startswith("ReadWritePaths="):
            need(v == "ReadWritePaths="+str(ORIGINAL),"changed original writable scope")
            props[i] = "ReadWritePaths=" + str(WORK)
        elif v.startswith("--setenv=TMPDIR="):
            props[i] = "--setenv=TMPDIR=" + str(TMP)
        elif v.startswith("BindsTo=") or v.startswith("After="):
            props[i] = v.split("=",1)[0] + "=" + ROOT_UNIT
        elif v.startswith("LimitFSIZE="):
            props[i] = "LimitFSIZE=12582912"
    props += ["--slice="+fit["SLICE"], "-p",
              f"TemporaryFileSystem={TMP}:rw,size=32M,nr_inodes=4096,mode=0700,nodev,nosuid,noexec",
              "-p","ReadOnlyPaths=/tmp /var/tmp","-p","WorkingDirectory="+str(TMP)]
    return props+["/usr/bin/python3","-IB",str(PACKAGE/"bootstrap.py"),"phase",str(grant_ref["path"]),
                  grant_ref["sha256"],label]


def write(path,data,mode=0o400):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_EXCL,mode)
    with os.fdopen(fd,"wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def grant(path, digest):
    g = checked({"path":str(path),"sha256":digest})
    need(Path(path).parent == BASE and HERE == PACKAGE and os.geteuid()==0 and __debug__ and sys.flags.isolated and
         g["owner"] == "/root" and g["schema"] == "horizon-native163-operator-bootstrap-grant-v1" and
         g["unit"] == ROOT_UNIT and g["slice"] == fit["SLICE"] and g["source_qualification_only"] is True and
         g["consumer_phases_authorized"] is False and g["restore_authorized"] is False and
         g["resource_credit_bytes"] == 0 and 0 < g["deadline"]-g["created"] <= 360 and
         g["created"] <= time.time() < g["deadline"], "invalid or expired bootstrap booking")
    package(PACKAGE,g["package_sha256"],["bootstrap.py","bootstrap_fit.py"])
    package(SOURCE,g["source_sha256"],["main.rs","phase.rs","PROTOCOL.json","consumer_capacity.rs"])
    mounted(g)
    return g


def child(g, label):
    fit["effective"](unit(label),actor=True)
    recipe,_ = fit["recipe"]()
    flags = [l.split() for l in Path("/proc/self/mountinfo").read_text().splitlines()]
    row, = [r for r in flags if r[4]==str(TMP)]
    fs = os.statvfs(TMP)
    need(row[row.index("-")+1]=="tmpfs" and {"rw","nodev","nosuid","noexec"} <= set(row[5].split(",")) and
         fs.f_blocks*fs.f_frsize <= 32*MIB and fs.f_files <= 4096 and not any(TMP.iterdir()) and
         Path(os.environ["TMPDIR"])==TMP, "unexpected compilation workspace")
    _,payload = original(recipe,label)
    if label=="ordinary-tests":
        payload[0]=str(WORK/"build-tests")
        before=checked({"path":str(BASE/"operator-source/deployment-seal-receipt.json"),"sha256":g["source_sha256"]})
        need(before["destination"]==str(SOURCE) and len(before["members"])==4,"different test source")
    else:
        need(payload[-3]==OLD_SOURCE and payload[-2]=="-o","unexpected source argument")
        payload[-3]=str(SOURCE/"main.rs")
        payload[-1]=str(TMP/"artifact")
    subprocess.run(payload,stdin=subprocess.DEVNULL,cwd=TMP,timeout=min(30,g["deadline"]-time.time()),check=True)
    if label!="ordinary-tests":
        output=TMP/"artifact"
        st=output.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=12*MIB,"wrong compiler output")
        data=output.read_bytes()
        end=output.lstat()
        need(len(data)==st.st_size and (st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns,st.st_size)==
             (end.st_dev,end.st_ino,end.st_mtime_ns,end.st_ctime_ns,end.st_size),"changed compiler output")
        write(WORK/label,data,0o500)


def held_lock(path, dev, ino):
    f=os.fdopen(os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC),"r+b")
    st=os.fstat(f.fileno())
    need((st.st_dev,st.st_ino,st.st_nlink)==(dev,ino,1) and stat.S_ISREG(st.st_mode),"wrong compiler lock")
    fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    return f


def root(g, binding):
    fit["effective"](ROOT_UNIT)
    need(g["deadline"]-time.time() >= 285, "insufficient time for original five actors and drainage")
    current = checked(g["price"])
    n = current["native"]
    fleet=checked(n["fleet"])
    price=fit["inspect_price"](n,fleet["retry9_auxiliary_commitments"],g["live_145_iid"],time.time())
    need(price == current["bootstrap"], "different exact source-QA price")
    rec, hashes = fit["recipe"]()
    need(current["original_commands"] == hashes and {p.name for p in WORK.iterdir()} <= {"lost+found","tmp"}
         and not any(TMP.iterdir()), "missing original commands or reused work")
    locks = [held_lock("/run/lock/horizon-epoch140-suffix-compiler.lock",29,1048),
             held_lock("/var/lib/jetstreamer/native16-compiler-suballocation-qualification-20261109-v1/native16-suballocation.lock",2304,4456819)]
    need(len(locks)==2,"compiler interlocks missing")
    outputs={}
    for index,label in enumerate(STAGES):
        need(g["deadline"]-time.time()>50*(len(STAGES)-index)+20,"original finite clock exhausted")
        fit["effective"](ROOT_UNIT)
        argv=child_argv(rec,label,binding)
        write(WORK/(label+".argv"),json.dumps(argv).encode())
        def log_bound():
            resource.setrlimit(resource.RLIMIT_FSIZE,(256<<10,256<<10))
        log=WORK/(label+".log")
        with log.open("xb") as out:
            p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,
                             timeout=50,preexec_fn=log_bound)
            out.flush();os.fsync(out.fileno())
        need(p.returncode==0,"failed phase "+label+"; original output at "+str(log))
        need(not (fit["SLICE_DIR"]/unit(label)/"cgroup.procs").exists() or
             not (fit["SLICE_DIR"]/unit(label)/"cgroup.procs").read_text().strip(),"undrained bootstrap child")
        if label=="ordinary-tests":
            need("11 passed; 0 failed" in log.read_text(),"missing original 11 tests")
        else:
            outputs[label]=file_sha(WORK/label)
        need(not any(TMP.iterdir()),"child leaked compiler scratch")
    proof=dict(source=g["source_sha256"],grant=binding,products=outputs,scope="operator bootstrap only",
               inherited_original_tests=11,build_145_concurrency=g["live_145_iid"],original_commands=hashes,
               resource_credit_bytes=0,consumer_phases_started=False,restore_started=False)
    write(WORK/"complete.json",json.dumps(proof,sort_keys=True).encode())


if __name__=="__main__":
    action,path,digest,*rest=sys.argv[1:]
    g=grant(path,digest)
    if action=="phase" and len(rest)==1:
        child(g,rest[0])
    elif action=="root" and not rest:
        root(g,{"path":path,"sha256":digest})
    else:
        raise SystemExit("expected root GRANT SHA or phase GRANT SHA LABEL")
