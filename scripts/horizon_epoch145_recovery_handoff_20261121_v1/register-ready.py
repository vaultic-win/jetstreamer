#!/usr/bin/python3 -IB
"""Register the V6 writer offer before waking the V12 epoch 145 dispatcher."""
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
DIR = RT / "epoch145-phase-dispatch-20261122-v1"
V6 = RT / "epoch136-joint-writer-20261122-v6"
SHARED = RT / "epoch145-v5e-delivery-handoff-20261121-v1/state"
BASE = Path("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1")
OP = Path("/run/horizon-epoch171-to136-g1.operation.lock")
LOCK = SHARED / "controller.lock"
DISPATCH = "horizon-145-phase-dispatch-20261122-v1.service"
OLD = "horizon-145-v5e-delivery-follow-20261121-v1.service"
SEMANTIC = "a99ed8b51e8a482b805b8a36a11b2700"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
HANDOFF = "1bd0e630eaecaf484afcf052ac96a0fe3cb6bfb36269a9cd01683065a542f999"
CADENCE = RT / "prefix140-status-cadence-20261122-v1/cadence-tools/deployment-seal-receipt.json"
V19 = RT / "incident-replay-fit-20261121-v1/tools-v19"
INSPECTION = "parent-registration-inspect.json"
NO_ACTION = ("parent_request_exists","reproduction_exists","actor_launched","remote_mutations","worker_initialize_authorized")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(doc):
    return (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode()


def binding(path, data):
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def raw(path):
    need(path.resolve(strict=True) == path, f"indirect evidence {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == m.st_gid == 0 and m.st_nlink == 1
             and not m.st_mode & 0o222 and 0 < m.st_size < 16 << 20, f"untrusted evidence {path}")
        data = f.read(m.st_size + 1)
        last = path.lstat()
        need(len(data) == m.st_size and os.path.samestat(m,last) and m.st_ctime_ns == last.st_ctime_ns,
             f"changed evidence {path}")
    return data


def ref(path):
    return binding(path, raw(path))


def read_ref(r):
    p = Path(r["path"])
    data = raw(p)
    need(binding(p,data) == r, f"wrong evidence digest {p}")
    return json.loads(data)


def dirfd(path):
    fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        m = os.fstat(fd)
        need(path.resolve(strict=True) == path and m.st_uid == m.st_gid == 0 and not m.st_mode & 0o022,
             f"unsafe registration directory {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def verify_bytes(path, data):
    need(raw(path) == data and stat.S_IMODE(path.lstat().st_mode) == 0o400, f"conflicting immutable {path}")
    return binding(path,data)


def publish(path, data):
    """Commit one whole immutable file without overwriting or exposing a prefix."""
    d = dirfd(path.parent)
    try:
        if not os.path.lexists(path):
            fd,tmp = tempfile.mkstemp(prefix=".register-"+path.name+"-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fchmod(f.fileno(),0o400)
                    os.fsync(f.fileno())
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.renameat2(d, os.fsencode(Path(tmp).name), d, os.fsencode(path.name), 1) != 0:
                    err = ctypes.get_errno()
                    if err != errno.EEXIST:
                        raise OSError(err, os.strerror(err), path)
            finally:
                Path(tmp).unlink(missing_ok=True)
        result = verify_bytes(path,data)
        os.fsync(d)
        return result
    finally:
        os.close(d)


def lock_identity(path):
    m=path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode) and m.st_nlink == 1
         and m.st_uid == m.st_gid == 0 and m.st_size == 0 and stat.S_IMODE(m.st_mode)==0o600,
         f"foreign lock {path}")
    return dict(path=str(path),device=m.st_dev,inode=m.st_ino)


def locks(identity):
    key = f"{os.major(identity['device']):02x}:{os.minor(identity['device']):02x}:{identity['inode']}"
    return [row.split()[1:] for row in Path("/proc/locks").read_text().splitlines() if key in row.split()]


def holder(identity, pid):
    rows=locks(identity)
    need(len(rows)==1 and rows[0][:4]==["FLOCK","ADVISORY","WRITE",str(pid)] and rows[0][-2:]==["0","EOF"],
         f"wrong exclusive lock owner {identity['path']}")
    proc=Path("/proc")/str(pid)
    for fd in (proc/"fd").iterdir():
        try:
            m=fd.stat()
            if (m.st_dev,m.st_ino)==(identity["device"],identity["inode"]):
                lines=(proc/"fdinfo"/fd.name).read_text().splitlines()
                if any(line.split()[2:]==rows[0] for line in lines if line.startswith("lock:")):
                    return
        except FileNotFoundError:
            continue
    raise ValueError("dispatcher lock descriptor missing")


@contextmanager
def operation(identity):
    fd=os.open(OP,os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        m=os.fstat(fd)
        need(lock_identity(OP)==identity and (m.st_dev,m.st_ino)==(identity["device"],identity["inode"]),
             "operation lock changed")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        holder(identity,os.getpid())
        yield
    finally:
        os.close(fd)


def unit(name):
    fields="Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,NRestarts,InvocationID,ControlGroup"
    out=subprocess.run(["/usr/bin/systemctl","show",name,"-p",fields],capture_output=True,text=True,timeout=15)
    v=dict(l.split("=",1) for l in out.stdout.splitlines())
    need(v["Id"]==name and (out.returncode==0 or (out.returncode==4 and v["LoadState"]=="not-found")),
         f"cannot identify {name}")
    return v


def drained(name, failed_invocation=None):
    v=unit(name)
    group=Path("/sys/fs/cgroup/system.slice")/name
    try:
        empty="populated 0" in (group/"cgroup.events").read_text().splitlines()
    except FileNotFoundError:
        empty=not group.exists()
    finished = v["ActiveState"] == "inactive" or (failed_invocation is not None and
        v["ActiveState"] == "failed" and v["InvocationID"] == failed_invocation)
    need(finished and not v["Job"] and v.get("MainPID","0")==v.get("ControlPID","0")=="0"
         and empty, f"{name} still owns work")


def clean_boundary(stage=SHARED, directory=DIR):
    for name in ("horizon-admit-136-actual-20261120-g1.service","horizon-qualify-136-actual-20261120-g1.service",
                 "horizon-guard-136-actual-20261120-g1.service","horizon-guard-136-actual-20261120-g1.timer"):
        drained(name)
    paths = [stage/name for name in ("post-full-submission.json","post-full-actor.json","publish-submission.json",
                                      "publish-actor.json","completed.json")]
    paths += [directory/"state"/name for name in ("post-selected.json","writer-selected.json","writer-exit.json")]
    paths += [BASE/name for name in ("prestart-intent.json","prestart-released.json","admission.json","reproduction",
                                     "parent-launch-request.json","capacity.json","donor171.json")]
    paths.append(Path("/run/horizon-epoch171-exclusive-to136-g1"))
    for p in paths:
        need(not os.path.lexists(p), f"registration crossed existing custody {p}")


def dispatcher_owner(pkg, seal_sha, unit_name, command, controller_locks):
    sealref=ref(pkg/"deployment-seal-receipt.json")
    need(sealref["sha256"]==seal_sha,"wrong dispatcher seal")
    seal=read_ref(sealref)
    need(seal["destination"]==str(pkg) and seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1"
         and seal["sealer_sha256"]==SEALER and seal["remote_mutations"] is False,"foreign selector deployment")
    image=pkg/"follow145"
    checker=ref(pkg/"boundary-inspector")
    for p in (image,Path(checker["path"])):
        rows=[m for m in seal["members"] if m["name"]==p.name]
        need(len(rows)==1 and rows[0]["mode"]=="0555" and rows[0]["sha256"]==ref(p)["sha256"]==checker["sha256"]
             and stat.S_IMODE(p.lstat().st_mode)==0o555, "selector image/inspector changed")
    v=unit(unit_name)
    pid=int(v["MainPID"])
    proc=Path("/proc")/str(pid)
    cg="/system.slice/"+unit_name
    need(v["ActiveState"]=="active" and v["SubState"]=="running" and not v["Job"] and v["ControlPID"]=="0"
         and v["NRestarts"]=="0" and re.fullmatch("[0-9a-f]{32}",v["InvocationID"]) and pid>1
         and v["ControlGroup"]==cg and (proc/"cgroup").read_text().strip()=="0::"+cg
         and (proc/"exe").samefile(image) and (proc/"exe").readlink()==image
         and (proc/"cmdline").read_bytes()==os.fsencode(image)+b"\0"+os.fsencode(command)+b"\0", "foreign selector generation")
    start=int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])
    for path in controller_locks:
        holder(lock_identity(path),pid)
    return dict(dispatcher=dict(pid=pid,start_ticks=start,invocation_id=v["InvocationID"]),deployment=sealref,
                boundary_inspector=checker)


def same_dispatcher(unit_name, owner):
    pid=owner["pid"]
    need(unit(unit_name)["InvocationID"]==owner["invocation_id"] and
         int((Path("/proc")/str(pid)/"stat").read_text().rsplit(") ",1)[1].split()[19])==owner["start_ticks"],
         "dispatcher changed while checking")


def observed_ready(seal_sha):
    identity=dispatcher_owner(DIR/"tools-v2",seal_sha,DISPATCH,"follow-v5e",[LOCK])
    drained(OLD)
    need(ref(V19/"post-stop-fit")["sha256"]=="cecfa99996f3099672c6e58f837f4aeef8c2818af57b8585839f128e164fcff5"
         and ref(V19/"deployment-seal-receipt.json")["sha256"]=="0ca8e1a8d4a5c927c14aa8020882f352db1f5e75abd2c4810fc80433cc312c0a",
         "different V19 price source")
    status=runpy.run_path(str(V19/"post-stop-fit"))["registered_status"]()
    status_seal=ref(CADENCE)
    need(status_seal["sha256"]=="7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e"
         and status["consumer_seal"]==status_seal,"different live status publisher")
    same_dispatcher(DISPATCH,identity["dispatcher"])
    return dict(schema="horizon-145-136-prestart-selector-ready-v1",boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                original_semantic_invocation=SEMANTIC,operation_lock=lock_identity(OP),
                **identity,status_consumer_seal=status_seal)


def handoff_inputs():
    proof=ref(V6/"PARENT_NATIVE_HANDOFF.json")
    need(proof["sha256"]==HANDOFF,"different qualified V6 parent proof")
    handoff=read_ref(proof)
    for key in ("parent","controller","parent_seal","controller_seal","launcher","mirror_price","mirror_price_seal"):
        need(ref(Path(handoff[key]["path"]))==handoff[key], f"changed V6 {key}")
    template=read_ref(handoff["prospective_writer_plan"])
    need("holding145_prestart_ready" not in template and template["controller_deployment"]==handoff["controller_seal"],
         "foreign prospective V6 plan")
    offer=dict(schema="horizon-136-registered-prestart-offer-v1",launcher=handoff["launcher"],parent=handoff["parent"],
               mirror_price=handoff["mirror_price"],prestart_evidence=proof)
    return template,offer


def inspect_plan(plan, parent):
    seal=read_ref(plan)["controller_deployment"]
    doc=json.loads(subprocess.check_output([parent["path"],"inspect",plan["path"],plan["sha256"],seal["path"],seal["sha256"]],
                                           timeout=45))
    need(doc["writer_plan"]==plan and doc["writer_deployment"]==seal and all(doc[k] is False for k in NO_ACTION),
         "parent accepted different inputs or observed work")
    return doc


def registration(directory, v6, observe, check_boundary, take_operation, operation_free, inputs, inspect, store=publish):
    """The state directory flock serializes concurrent registrars across the READY-last window."""
    state_fd=dirfd(directory/"state")
    try:
        fcntl.flock(state_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ready=observe()
        ready_bytes=encoded(ready)
        path=directory/"READY.json"
        pin=binding(path,ready_bytes)
        template,fields=inputs()
        plan_bytes=encoded(dict(template,holding145_prestart_ready=pin))
        plan_path=v6/"registered-production-plan.json"
        plan=binding(plan_path,plan_bytes)
        offer_bytes=encoded(dict(fields,selector=pin,writer_plan=plan))
        offer_path=directory/"OFFER.json"
        proof_path=directory/"state"/INSPECTION
        if os.path.lexists(path):
            verify_bytes(path,ready_bytes)
            verify_bytes(plan_path,plan_bytes)
            verify_bytes(offer_path,offer_bytes)
            proof=read_ref(ref(proof_path))
            need(proof["selector"]==pin and proof["parent"]==fields["parent"] and
                 proof["inspection"]["writer_plan"]==plan and all(proof["inspection"][k] is False for k in NO_ACTION),
                 "prior registration inspection differs")
        else:
            with take_operation(ready["operation_lock"]):
                check_boundary()
                need(ready==observe(),"dispatcher changed before plan")
                need(store(plan_path,plan_bytes)==plan,"different V6 plan")
                doc=inspect(plan,fields["parent"])
                store(proof_path,encoded(dict(selector=pin,parent=fields["parent"],inspection=doc)))
                check_boundary()
                need(ready==observe(),"dispatcher changed before offer")
                store(offer_path,offer_bytes)
            check_boundary()
            need(ready==observe(),"dispatcher changed before READY")
            operation_free(ready["operation_lock"])
            store(path,ready_bytes)
        return dict(ready=pin,offer=ref(offer_path),writer_plan=plan,parent_inspection=ref(proof_path))
    finally:
        os.close(state_fd)


def main():
    need(os.geteuid()==0 and sys.flags.isolated and __debug__, "isolated root operator required")
    need(len(sys.argv)==2 and re.fullmatch("[a-f0-9]{64}",sys.argv[1]), "register-ready.py DISPATCH_TOOLS_V2_SEAL_SHA256")
    def check_free(identity):
        need(lock_identity(OP)==identity and not locks(identity),"operation lock occupied before READY")
    print(json.dumps(registration(DIR,V6,lambda:observed_ready(sys.argv[1]),clean_boundary,operation,
                                  check_free,handoff_inputs,inspect_plan),sort_keys=True))


if __name__=="__main__":
    main()
