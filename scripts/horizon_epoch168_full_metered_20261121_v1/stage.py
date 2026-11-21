#!/usr/bin/python3 -I
"""Seal the producer gate and prepare its empty run tree on the home-backed runtime."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("production",HERE/"production.py")
producer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
STATE=producer.STATE
SEALER=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def raw(value):
    return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()


def store(path,data):
    if path.exists():
        producer.need(path.is_file() and path.read_bytes()==data,f"conflicting staged evidence: {path}")
        return
    with path.open("xb") as f:
        f.write(data)
        os.fchmod(f.fileno(),0o444)
        f.flush()
        os.fsync(f.fileno())


def empty_tree(root,j):
    paths={root,root/"private",root/"ledger",root/"runtime"}
    files={root/"producer.log"}
    for target in producer.projection(j):
        if not target.is_relative_to(producer.RUN):
            continue
        child=root/target.relative_to(producer.RUN)
        files.add(child)
        for parent in child.parents:
            if parent==root:
                break
            paths.add(parent)
    for p in sorted(paths,key=lambda x:len(x.parts)):
        if not p.exists():
            p.mkdir(mode=0o700)
            os.chown(p,1001,1003)
        m=p.lstat()
        producer.need(stat.S_ISDIR(m.st_mode) and (m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(1001,1003,0o700),
            f"wrong private staging directory: {p}")
    for p in files:
        if not p.exists():
            with p.open("xb") as f:
                os.fchown(f.fileno(),1001,1003)
                os.fchmod(f.fileno(),0o600)
        m=p.lstat()
        producer.need(stat.S_ISREG(m.st_mode) and m.st_size==0 and m.st_nlink==1
                      and m.st_uid==1001 and m.st_gid==1003 and stat.S_IMODE(m.st_mode)==0o600,
                      f"occupied or foreign staging file: {p}")
    producer.need({root,*root.rglob("*")}==paths|files,"unexpected staged entry")
    return sorted(str(p.relative_to(root)) for p in paths|files)


def main():
    producer.need(os.geteuid()==0,"root staging required")
    os.umask(0o077)
    j,argv=producer.normal_spec()
    producer.need(not producer.RUN.exists(),"the planned production run root already exists")
    empty=empty_tree(STATE/"prepared-run",j)
    for name in ("barrier","guard-receipts"):
        (STATE/name).mkdir(mode=0o700,exist_ok=True)
    # The producer sees the root-owned permit directory through a read-only bind.
    # It needs search permission on that directory once bound in its own namespace.
    (STATE/"barrier").chmod(0o711)
    producer.need(not (STATE/"barrier/allow").exists(),"stale release permit")
    source=STATE/"controller-source"
    source.mkdir(mode=0o700,exist_ok=True)
    for name in ("gate.py","production.py","registration.py"):
        store(source/name,(HERE/name).read_bytes())
    controller=STATE/"controller"
    seal_plan={"schema":"jetstreamer-sealed-deployment-plan-v1","destination":str(controller),
               "members":[dict(name=n,source=str(source/n),sha256=sha(source/n),mode=0o444) for n in ("gate.py","production.py","registration.py")]}
    plan_path=STATE/"controller-seal-plan.json"
    store(plan_path,raw(seal_plan))
    producer.need(sha(SEALER)==SEALER_SHA,"wrong normal deployment sealer")
    if not controller.exists():
        subprocess.run([SEALER,plan_path,"--plan-sha256",sha(plan_path),"--self-sha256",SEALER_SHA],check=True)
    subprocess.run(["/usr/bin/sha256sum","--check","--status","SHA256SUMS"],cwd=controller,check=True)
    for p in seal_plan["members"]:
        producer.need(sha(controller/p["name"])==p["sha256"],"sealed gate differs")
    gate_spec=importlib.util.spec_from_file_location("qualified_gate",controller/"gate.py")
    gated=importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gated)
    permit_probe=STATE/"private-permit-control"
    permit_probe.mkdir(mode=0o700,exist_ok=True)
    positive=permit_probe/"allow"
    test_iid="0123456789abcdef0123456789abcdef"
    store(positive,test_iid.encode())
    producer.need(not gated.permit_matches(permit_probe/"absent",test_iid),"missing permit accepted")
    try:
        gated.permit_matches(positive,test_iid)
    except RuntimeError:
        pass
    else:
        raise ValueError("writable mount accepted for root permit")
    # The transient helper has its own mount namespace. The production barrier stays empty.
    need_private_mount=(Path("/proc/self/ns/mnt").stat().st_ino != Path("/proc/1/ns/mnt").stat().st_ino)
    producer.need(need_private_mount,"permit control requires a private mount namespace")
    subprocess.run(["/usr/bin/mount","--bind",permit_probe,permit_probe],check=True)
    try:
        subprocess.run(["/usr/bin/mount","-o","remount,bind,ro",permit_probe],check=True)
        producer.need(gated.permit_matches(positive,test_iid),"genuine root-controlled permit rejected")
        try:
            gated.permit_matches(positive,"f"*32)
        except RuntimeError:
            pass
        else:
            raise ValueError("wrong-invocation permit accepted")
    finally:
        subprocess.run(["/usr/bin/umount",permit_probe],check=True)
    registration_spec=importlib.util.spec_from_file_location("qualified_registration",controller/"registration.py")
    registration=importlib.util.module_from_spec(registration_spec)
    registration_spec.loader.exec_module(registration)
    prior=producer.verified(registration.TRACE,registration.TRACE_SHA)
    original_sample=registration.bound(prior["last_guard"])
    original_plan={"sha256":original_sample["plan_sha256"]}
    registration.guard_sample(original_sample,original_plan,prior["invocation"],prior["original_pid"])
    for attr,value in (("trip_reason","guard trip"),("producer_stop_enabled",False),("plan_sha256","0"*64),
                       ("producer_invocation_id","0"*32)):
        changed={**original_sample,attr:value}
        try:
            registration.guard_sample(changed,original_plan,prior["invocation"],prior["original_pid"])
        except ValueError:
            pass
        else:
            raise ValueError("registration accepted altered guard evidence: "+attr)
    try:
        registration.main()
    except ValueError as error:
        producer.need(str(error)=="original producer PID or budget differs",str(error))
    else:
        raise ValueError("unlaunched synthetic producer registered")
    store(STATE/"PRODUCER_ARGV.json",raw(argv))
    synthetic="0123456789abcdef0123456789abcdef"
    plan,native=producer.guard(j,synthetic,producer.MINIMUM_FLOOR)
    fixture=STATE/"STATIC_GUARD_PLAN.json"
    store(fixture,raw(plan))
    i=native.index("--plan-sha256")
    native[i-1]=str(fixture)
    response=subprocess.run(native[i-2:]+["--validate-plan-only"],capture_output=True,text=True,check=True)
    checked=json.loads(response.stdout)
    producer.need(checked["validated"] and checked["resource_samples_taken"]==0 and not checked["producer_signaled"]
                  and not checked["protective_guard_proven"] and checked["unit"]==j["producer_unit"],
                  "guard did not confirm the exact unlaunched whole-tree plan")
    store(STATE/"STATIC_GUARD_RESULT.json",raw(checked))
    info=dict(schema="horizon-168-guarded-full-producer-staged-v1",unit=j["producer_unit"],ready_tree=str(STATE/"prepared-run"),
          ready_entries=empty,production_path=str(producer.RUN),producer_argv_sha256=sha(STATE/"PRODUCER_ARGV.json"),
          native_input_seal=sha(producer.PKG/"deployment-seal-receipt.json"),controller_seal=sha(controller/"deployment-seal-receipt.json"),
          private_native_controls_sha256=sha(Path(producer.complete_offline())),guard_static=checked,
          permit_controls=["absent","writable-mount","correct-original-iid","foreign-iid"],
          registration_controls=["previous-sample-structure","trip","disabled-protection","wrong-plan","wrong-invocation","absent-producer"],
          current_producer_started=False,barrier_released=False,resource_credits=0)
    store(STATE/"PREPARED.json",raw(info))
    print(json.dumps(info,sort_keys=True))


if __name__=="__main__":
    main()
