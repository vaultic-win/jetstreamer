"""Use the closed hourly allocation for one guarded generation-bound bootstrap copy."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = RT / "epoch143-second-hourly-20261128-v1"
PACKAGE = BASE / "preparation-tools-v1"
RUN = Path("/home/sol/.jetstreamer-private") / BASE.name
INPUT = RUN / "input"
UNIT = "horizon-prepare-143-hourly-copy-20261128-v1"
GUARD = UNIT + "-guard"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
PRICE = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v18"
PRICE_SHA = "8c326db152e86c7723771501a225607de66012c6cc6f619e9da452335c627e4a"
SOURCE = "gs://mainnet-beta-ledger-us-ny5/61775538/hourly/snapshot-61787631-2y3Q8vdnvB77rU4KHomsesrMWeTPrh9hsp9shn1uEwus.tar.zst#1634786651485428"
BOOTSTRAP = INPUT / SOURCE.rsplit("/",1)[1].split("#",1)[0]
DEST_RECEIPT = INPUT / "GENERATION_CUSTODY.json"
BYTES = 2_350_018_921
M = 1 << 20
MAX_BYTES = BYTES + 64*M
MEM = 512*M
RUNTIME = 720
GUARD_PROPS = "Id,InvocationID,MainPID,ControlPID,ActiveState,SubState,Job"


def need(ok, failure):
    if not ok:
        raise ValueError(failure)


def ref(path):
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def save(path, record, mode=0o400):
    data = json.dumps(record,indent=2,sort_keys=True).encode() + b"\n"
    tmp = path.with_name(".pending-" + path.name)
    fd = os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(),mode)
            os.fsync(f.fileno())
        os.link(tmp,path,follow_symlinks=False)
    finally:
        tmp.unlink()
    directory = os.open(path.parent,os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return ref(path)


def run(*argv, timeout=25):
    return subprocess.check_output(argv,text=True,timeout=timeout)


def native(unit, fields=GUARD_PROPS, not_found=False):
    p = subprocess.run(["/usr/bin/systemctl","show","--all","-p",fields,unit],
                       text=True,capture_output=True,timeout=8)
    need(p.returncode in ((0,4) if not_found else (0,)), "cannot read native unit " + unit)
    return dict(line.split("=",1) for line in p.stdout.splitlines())


def sealed(directory, sha=None):
    metadata = directory / "deployment-seal-receipt.json"
    seal = json.loads(metadata.read_bytes())
    need(seal["destination"] == str(directory) and (sha is None or ref(metadata)["sha256"] == sha),
         "changed protected preparation package")
    for row in seal["members"]:
        p = directory / row["name"]
        need(p.parent == directory and p.resolve(strict=True) == p and p.stat().st_uid == 0
             and not p.stat().st_mode & 0o222 and p.stat().st_size == row["bytes"]
             and ref(p)["sha256"] == row["sha256"], "unsealed preparation member " + row["name"])
    return ref(metadata)


def wait_until(get, description, limit=26):
    deadline = time.monotonic()+limit
    while time.monotonic() < deadline:
        result = get()
        if result:
            return result
        time.sleep(0.15)
    raise ValueError(description)


def first_guard():
    files = sorted((BASE / "copy-guard").glob("sample-*.json"))
    if not files:
        return None
    sample = files[0]
    row = json.loads(sample.read_bytes())
    guard_iid = row["guard_invocation_id"]
    lines = run("/usr/bin/journalctl","-q","--no-pager","-o","json",
                "_PID=1","_UID=0","UNIT="+GUARD+".service","INVOCATION_ID="+guard_iid).splitlines()
    terminal = [json.loads(x) for x in lines if '"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"' in x]
    return (sample,row,terminal[0]) if len(terminal) == 1 else None


def dispatch():
    need(os.geteuid() == 0 and Path(__file__).resolve().parent == PACKAGE,"use the sealed 143 preparation tool")
    package = sealed(PACKAGE)
    capacity = sealed(PRICE,PRICE_SHA)
    with LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(INPUT.is_dir() and INPUT.resolve() == INPUT and INPUT.stat().st_uid == 1001
             and not INPUT.stat().st_mode & 0o077 and not list(INPUT.iterdir()),
             "copy input needs an empty owner-only HOME leaf")
        for name in (UNIT+".service", GUARD+".timer", GUARD+".service"):
            row = native(name,"Id,ActiveState,LoadState,Job",not_found=True)
            need(row["LoadState"] == "not-found" and not row["Job"],"a preparation invocation already exists")
        quote = runpy.run_path(str(PRICE/"capacity.py"))["prepare143_roster"]()
        need(quote["package"] == capacity and quote["preparation_only"] and quote["fits"]
             and quote["closed_143"]["retained_ram"] == 41<<30
             and quote["closed_143"]["retained_home"] == (64<<30)+64*M
             and quote["resource_credit_bytes"] == 0 and quote["home_margin"] >= MAX_BYTES
             and quote["ram_margin"] >= 0 and 0 <= time.time()-quote["recorded_unix_seconds"] < 20,
             "closed 143 preparation lacks fresh full capacity")
        floor = quote["required_home"]
        intent = save(BASE/"COPY_ADMISSION.json",dict(
            schema="horizon-143-guarded-copy-admission-v1",source=SOURCE,snapshot_bytes=BYTES,
            memory=MEM,cap=MAX_BYTES,home_reserved_once=True,guard_floor=floor,
            capacity=quote,package=package,replay_authorized=False,resource_credit_bytes=0))
        pinned = json.loads((RT/"epoch143-bootstrap-custody-20261126-v1/GENERATION_CUSTODY.json").read_bytes())
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        active = False
        permitted = False
        try:
            run("/usr/bin/systemd-run","--no-block","--unit="+UNIT,
                "--property=Type=exec","--property=Restart=no","--property=User=sol","--property=Group=horizon",
                "--property=CPUQuota=50%",f"--property=MemoryMax={MEM}","--property=MemorySwapMax=0",
                "--property=TasksMax=128",f"--property=RuntimeMaxSec={RUNTIME}s","--property=TimeoutStartSec=80s",
                "--property=UMask=0077","--property=NoNewPrivileges=yes","--property=ProtectHome=read-only",
                "--property=ProtectSystem=strict","--property=PrivateTmp=yes",
                f"--property=ReadWritePaths={INPUT} /home/sol/.config/gcloud",
                f"--property=LimitFSIZE={BYTES}","--setenv=CLOUDSDK_CONFIG=/home/sol/.config/gcloud",
                "--setenv=CLOUDSDK_STORAGE_PARALLEL_PROCESS_COUNT=1","--setenv=CLOUDSDK_STORAGE_PARALLEL_THREAD_COUNT=1",
                "--setenv=CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_MAX_COMPONENTS=1",
                f"--property=BindReadOnlyPaths={PACKAGE}:/run/horizon143-prep-tools {BASE / 'permits'}:/run/horizon143-preparation-permits",
                "--property=ExecStartPre=/usr/bin/python3 -IB /run/horizon143-prep-tools/prepare143_second_gate.py copy",
                "--","/usr/bin/python3","-IB","/run/horizon143-prep-tools/restore_bound_gcs_snapshot.py",
                "--gcloud-bin=/usr/bin/gcloud","--gcloud-account="+pinned["gcloud_account"],
                "--billing-project="+pinned["billing_project"],"--versioned-uri="+SOURCE,
                "--destination="+str(BOOTSTRAP),"--receipt="+str(DEST_RECEIPT),f"--expected-size={BYTES}",
                "--expected-crc32c=w7Xg4w==","--expected-md5=NMBdYE4IMm4fIxcYNVPdkg==",
                "--filesystem="+str(INPUT),f"--minimum-free-bytes={floor}")
            active = True
            def starting():
                row = native(UNIT+".service")
                return row if row["ActiveState"]=="activating" and row["SubState"]=="start-pre" and row["ControlPID"]!="0" else None
            actor = wait_until(starting,"copy never reached the native pre-start gate")
            iid = actor["InvocationID"]
            guard = PACKAGE/"guard-preparation"
            info = INPUT.stat()
            run("/usr/bin/systemd-run","--unit="+GUARD,"--on-active=1s","--on-unit-inactive=4s",
                "--timer-property=AccuracySec=1s","--timer-property=BindsTo="+UNIT+".service",
                "--property=Type=oneshot","--property=MemoryMax=1G","--property=MemorySwapMax=0",
                "--property=CPUQuota=100%","--property=TasksMax=32","--property=TimeoutStartSec=25s",
                "--",str(guard),"--unit",UNIT+".service","--expected-invocation-id",iid,
                "--self-sha256",ref(guard)["sha256"],"--root",str(INPUT),"--root-uid",str(info.st_uid),
                "--root-device",str(info.st_dev),"--root-inode",str(info.st_ino),
                "--receipt-directory",str(BASE/"copy-guard"),"--minimum-free-bytes",str(floor),
                "--maximum-root-bytes",str(MAX_BYTES),"--expected-memory-max-bytes",str(MEM),
                "--expected-memory-swap-max-bytes","0","--expected-tasks-max","128",
                "--expected-cpu-quota-usec","500000","--expected-max-run-usec",str(RUNTIME*1_000_000))
            path, sample, terminal = wait_until(first_guard,"copy guard never produced a clean native first fire")
            need(native(UNIT+".service")==actor and sample["actor_invocation_id"]==iid and not sample["trip"]
                 and sample["native_owner_stable"] and sample["original_native_ActiveState"]=="activating"
                 and sample["original_native_SubState"]=="start-pre" and sample["original_native_MainPID"]==0
                 and sample["original_native_ControlPID"]==int(actor["ControlPID"])
                 and sample["available_bytes"]>=floor and sample["minimum_free_bytes"]==floor
                 and sample["conservative_physical_bytes"]<=MAX_BYTES and sample["maximum_root_bytes"]==MAX_BYTES,
                 "copy first guard does not cover the original pre-start actor")
            issued = save(BASE/"permits"/f"copy-{iid}.json",dict(
                schema="horizon-143-preparation-permit-v1",unit=UNIT+".service",boot_id=boot,invocation=iid,
                admission=intent,guard=ref(path),guard_terminal_cursor=terminal["__CURSOR"],first_guard_success=True,
                replay_authorized=False,resource_credit_bytes=0),0o444)
            permitted = True
            print(json.dumps(dict(actor=actor,permit=issued,guard=ref(path),intent=intent)))
        finally:
            if active and not permitted:
                for target in (GUARD+".timer",GUARD+".service",UNIT+".service"):
                    subprocess.run(["/usr/bin/systemctl","stop",target],check=False,timeout=25)


if __name__ == "__main__":
    dispatch()
