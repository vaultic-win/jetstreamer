#!/usr/bin/python3
"""Prepare or start only the sealed Foundation epoch 229 v334 diagnostic."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

BASE = Path("/var/lib/jetstreamer/horizon229-bank-delta-v334")
CONTROL = BASE.parent / "horizon-seven-publication-controller-v222"
PROFILE_SHA = "7506d3180e37e565791401a1ed7398d9caf55b5397e70a1ad18081c10108b85c"
CHECK_SHA = "1e40223295f03168fcc494a16133b02f60ffe73c6e80e62c3f73ae5904dac15f"
STARTUP = BASE.parent / "horizon292-full-v322/admit.py"
STARTUP_SHA = "f32b86c421bc987852120912574fe72c0f59cfbf19bfc021a69dbe8ae4a5049f"
TERMINAL292 = BASE.parent / "horizon292-full-v322/terminal.json"
TERMINAL292_SHA = "81cf3186abb14fb2033104606e761baa0b57b1d6468d206ca28511e1fffef48d"
PRESTART = BASE.parent / "horizon229-trace-ram-tokens-v325/pre-start.sh"
PRESTART_SHA = "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0"

# The probe receives the five readonly bindings and the actual worker settings.
# The only subprocess it can run is the worker's Hello/Ping/Shutdown exchange.
PROBE = r"""
import hashlib,json,os,stat,struct,subprocess,sys,tempfile
from pathlib import Path
p=json.loads(sys.argv[1])
assert os.getuid()==1000
def metadata(path):
    stamp=Path(path).stat()
    return (stamp.st_dev,stamp.st_ino,stamp.st_size)
def sha(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file,'sha256').hexdigest()
for row in p['mounts']:
    path=row['target']
    assert metadata(path)==tuple(row[key] for key in ('device','inode','size')),path
    assert os.statvfs(path).f_flag&os.ST_RDONLY,path
for role in ('node','worker'):
    row=p[role]
    assert os.access(row['path'],os.X_OK) and sha(row['path'])==row['sha256'],role
    assert os.statvfs(row['path']).f_flag&os.ST_RDONLY,role
snapshot=p['snapshot']
assert metadata(snapshot['path'])==tuple(snapshot[key] for key in ('device','inode','size'))
assert os.statvfs(snapshot['path']).f_flag&os.ST_RDONLY
for name,value in p['environment'].items():
    assert os.environ.get(name)==value,name
trace=Path(p['environment']['JETSTREAMER_EPOCH229_BANK_TRACE_DIR'])
mode=trace.lstat()
assert stat.S_ISDIR(mode.st_mode) and mode.st_uid==1000 and stat.S_IMODE(mode.st_mode)==0o700
assert trace.stat().st_dev==Path(p['mountpoint']).stat().st_dev
assert not any(trace.iterdir())
with tempfile.NamedTemporaryFile(dir=trace,prefix='.namespace-fixture-') as probe:
    probe.write(b'epoch 229 trace directory fixture')
    probe.flush()
assert not any(trace.iterdir())
def frame(payload):
    return struct.pack('<I',len(payload))+payload
request=frame(struct.pack('<QIH',1,0,5))+frame(struct.pack('<QI',2,4))+frame(struct.pack('<QI',3,5))
worker=subprocess.run([p['worker']['path']],input=request,capture_output=True,timeout=10,check=True)
assert not worker.stderr
assert hashlib.sha256(worker.stdout).hexdigest()=='01c3a645a8132bdf0a9c29b86bc5d0439e80db94d5549aea688da2e231a75b1b'
print(json.dumps(dict(namespace_verified=True,started_replay=False,readonly_mounts=len(p['mounts']),old_protocol_bytes_match=True,
                      trace_directory=str(trace),resource_samples_taken=0,remote_mutations=False,r2_mutations=False)))
"""

def run(*argv, timeout=18):
    return subprocess.check_output([str(a) for a in argv], text=True, timeout=timeout).strip()

def ref(path):
    with Path(path).open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    return {"path": str(path), "sha256": digest}

def bound(binding):
    assert ref(binding["path"]) == binding,binding
    return json.loads(Path(binding["path"]).read_text())

def checked_file(path, digest):
    assert path.is_file() and path.resolve() == path,path
    stamp=path.stat()
    assert stamp.st_uid==0 and stamp.st_mode&0o222==0,path
    assert ref(path)["sha256"]==digest,path

def record(path, data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,"w") as out:
        json.dump(data,out,indent=2,sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)

def check(static_only=False):
    checked_file(BASE/"check.py",CHECK_SHA)
    flags=["--static-only"] if static_only else []
    result=subprocess.run([sys.executable,"-I","-B",str(BASE/"check.py"),*flags],capture_output=True,text=True,timeout=20)
    if result.returncode not in (0,2) or (static_only and result.returncode):
        raise RuntimeError(result.stderr or result.stdout)
    return json.loads(result.stdout)

def mountpoint(path):
    if not path.exists():
        path.mkdir(mode=0o711)
        path.chmod(0o711)
    mode=path.lstat()
    assert path.resolve()==path and stat.S_ISDIR(mode.st_mode)
    assert mode.st_uid==0 and stat.S_IMODE(mode.st_mode)==0o711,path
    assert not path.is_mount() and not any(path.iterdir()),path

def setup_namespace(profile, ns):
    root=Path(ns["mountpoint"])
    assert root==Path(profile["filesystem"])
    run("mount","-t","tmpfs","-o",ns["mount_options"],"tmpfs",root)
    native=run("findmnt","-T",root,"-n","-o","FSTYPE,OPTIONS").split(maxsplit=1)
    assert native[0]=="tmpfs" and {"rw","nosuid","nodev","noswap"}<=set(native[1].split(","))
    fs=os.statvfs(root)
    assert fs.f_bavail*fs.f_frsize>=profile["ram_scratch_cap_bytes"]+(2<<30)
    for directory in sorted(map(Path,ns["dirs_mode_0700_owned_ubuntu"]),key=lambda path:len(path.parts)):
        assert directory.is_relative_to(root) and directory!=root
        directory.mkdir(mode=0o700)
        os.chown(directory,1000,1000)
    for row in ns["readonly_mounts"]:
        dest=Path(row["target"])
        assert dest.is_relative_to(root) and dest.parent.is_dir()
        fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        os.close(fd)

def expected_environment(profile):
    return {
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_20":profile["worker"]["path"],
        "JETSTREAMER_HISTORICAL_TRACE":"1",
        "JETSTREAMER_EPOCH229_BANK_TRACE_DIR":profile["trace_dir"],
        "JETSTREAMER_PRIVATE_RUN_ROOT":profile["run_root"]+"/state",
    }

def probe_payload(profile,ns):
    return json.dumps({"mountpoint":profile["filesystem"],"mounts":ns["readonly_mounts"],
                       "node":profile["node"],"worker":profile["worker"],"snapshot":profile["bootstrap"],
                       "environment":expected_environment(profile)})

def rehearsed_namespace(profile,ns,parent_pid):
    assert parent_pid==os.getppid()
    for namespace in ("mnt","net"):
        assert os.readlink(f"/proc/self/ns/{namespace}")!=os.readlink(f"/proc/{parent_pid}/ns/{namespace}")
    setup_namespace(profile,ns)
    pairs=[(row["source"],row["target"]) for row in ns["readonly_mounts"]]
    pairs.extend((profile[k]["path"],profile[k]["path"]) for k in ("node","worker","bootstrap"))
    for source,target in pairs:
        run("mount","--bind",source,target)
        run("mount","-o","remount,bind,ro",target)
    env=[f"{key}={value}" for key,value in expected_environment(profile).items()]
    return json.loads(run("runuser","-u","ubuntu","--","env","-i","PATH=/usr/bin:/bin",*env,
                           "/usr/bin/python3","-I","-B","-c",PROBE,probe_payload(profile,ns)))

def namespace_preflight(profile,ns):
    check(static_only=True)
    path=Path(profile["filesystem"])
    existed=path.exists()
    mountpoint(path)
    try:
        answer=run("unshare","--mount","--net","--propagation","private",
                   sys.executable,"-I","-B",Path(__file__).resolve(),"--namespace-child",
                   os.getpid(),timeout=40)
        return json.loads(answer)
    finally:
        assert not path.is_mount() and not any(path.iterdir()),path
        if not existed:
            path.rmdir()

def exact_inventory(ops):
    image=ops.checked_image(ops.R2)
    result=json.loads(run("systemd-run","--quiet","--wait","--pipe","--collect",
        "--unit=foundation-229-bank-delta-inventory-v334","--property=Type=exec",
        "--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
        "--setenv=TOKIO_WORKER_THREADS=2","--",image,"inventory","/home/ubuntu/horizon",
        "--epochs","229-229","--receipt-directory","/home/ubuntu/.jetstreamer-private/r2-receipts",
        timeout=45))
    assert result["schema"]=="jetstreamer-horizon-r2-inventory-v1" and result["anomalies"]==0
    row,=result["entries"]
    assert row["epoch"]==229 and row["state"]=="missing",row
    return row

def startup(profile,fit,inventory,namespace,kit,actor_properties):
    ops,starter,runner=kit.ops,kit.startup,kit.replay
    unit,guard,timer=profile["unit"],profile["guard_unit"],profile["guard_timer"]
    argv=profile["argv"]
    admission=record(BASE/"admission.json",{
        "schema":"foundation-epoch229-bank-delta-admission-v334","controller":runner.THREAD,
        "epoch":229,"profile":ref(BASE/"profile.json"),"fit":fit,
        "namespace":namespace,"exact_inventory":inventory,"issued_unix_seconds":int(time.time()),
        "admitted":True,"canonical_epoch_publication_authorized":False,
    })
    iid=None
    guard_started=False
    token_released=False
    try:
        starter.systemd_run(unit,actor_properties,argv,"--slice=system.slice")
        def dormant():
            p=ops.props(unit,["InvocationID","ActiveState","SubState","ControlPID","MainPID","ControlGroup"])
            if (p["ActiveState"],p["SubState"],p["MainPID"])==("activating","start-pre","0") and int(p["ControlPID"])>0:
                return p
            return None
        prestart=starter.until(dormant,12)
        iid=prestart["InvocationID"]
        assert re.fullmatch("[a-f0-9]{32}",iid) and prestart["ControlGroup"]=="/system.slice/"+unit
        cg=Path("/sys/fs/cgroup"+prestart["ControlGroup"])
        limits={key:(cg/key).read_text().strip() for key in ("memory.max","memory.high","memory.swap.max","pids.max","cpu.max","cpuset.cpus.effective")}
        quota,period=map(int,limits["cpu.max"].split())
        assert [limits[key] for key in ("memory.max","memory.high","memory.swap.max","pids.max","cpuset.cpus.effective")]==[
            str(profile["memory_max_bytes"]),str(profile["memory_high_bytes"]),"0","512","80-87"]
        assert quota==8*period
        record(BASE/"native-prestart.json",dict(owner=prestart,limits=limits))
        plan=record(BASE/"guard-plan.json",dict(bound(profile["static_plan"]),invocation_id=iid))
        receipts=BASE/"guard-receipts"
        runner.PRODUCER,runner.GUARD_UNIT,runner.TIMER,runner.RECEIPTS=unit,guard,timer,receipts
        runner.GUARD_SHA=profile["guard"]["sha256"]
        gprops=["--property=Type=oneshot","--property=User=root","--property=UMask=0077",
                "--property=Restart=no","--property=MemoryMax=1G","--property=MemorySwapMax=0",
                "--property=CPUQuota=100%","--property=TasksMax=256","--property=TimeoutStartSec=90",
                "--property=ProtectSystem=strict","--property=ProtectHome=read-only","--property=PrivateNetwork=yes",
                "--property=NoNewPrivileges=yes","--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
                "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",f"--property=ReadWritePaths={receipts}"]
        starter.systemd_run(guard,gprops,[profile["guard"]["path"],plan["path"],"--plan-sha256",plan["sha256"],
                          "--self-sha256",runner.GUARD_SHA],"--on-active=1s","--on-unit-inactive=60s",
                          "--timer-property=AccuracySec=1s","--timer-property=RandomizedDelaySec=0")
        guard_started=True
        first,sample=starter.until(lambda:runner.first_guard(iid,plan),35)
        clock,deadline=starter.until(runner.timer_ready,15)
        assert dormant()==prestart and not sample["root_physical_observation_error"]
        assert sample["available_bytes"]>=2<<30 and sample["maximum_root_physical_bytes"]==profile["ram_scratch_cap_bytes"]
        token_dir=Path(profile["token_root"])/iid
        token_dir.mkdir(mode=0o755)
        token_dir.chmod(0o755)
        token=record(token_dir/"guard-admission.json",{
            "schema":"foundation-epoch229-bank-delta-first-guard-v334","epoch":229,"unit":unit,
            "invocation_id":iid,"guard_invocation_id":sample["guard_invocation_id"],
            "sample":first,"admission":admission,"guard_plan":plan,
            "guard_timer_invocation":clock["InvocationID"],"next_guard_monotonic_usec":deadline,
            "canonical_epoch_publication_authorized":False,
        })
        token_released=True
        def running():
            owner=ops.props(unit,["InvocationID","ActiveState","SubState","MainPID","NRestarts","ControlGroup","Result","LoadState"])
            if (owner["ActiveState"],owner["SubState"])!=("active","running"):
                return None
            pid=int(owner["MainPID"])
            assert owner["InvocationID"]==iid and owner["NRestarts"]=="0" and pid>0
            if not Path(f"/proc/{pid}/exe").samefile(profile["node"]["path"]):
                return None
            for sample_path in sorted(receipts.glob("sample-*.json"),key=lambda p:p.stat().st_mtime_ns,reverse=True):
                sampled=ref(sample_path)
                row=bound(sampled)
                if row["producer"]["active"]!="active" or not row["workers"]:
                    continue
                assert row["producer_invocation_id"]==iid and row["producer"]["pid"]==pid and row["plan_sha256"]==plan["sha256"]
                assert row["trip_reason"] is None and row["worker_observation_error"] is None
                matching_worker=False
                for worker_pid,_ in row["workers"]:
                    proc=Path(f"/proc/{worker_pid}")
                    try:
                        if (proc/"cgroup").read_text().strip()!="0::"+owner["ControlGroup"]:
                            continue
                        image=(proc/"exe").resolve(strict=True)
                        if image.is_relative_to(profile["run_root"]) and ref(proc/"exe")["sha256"]==profile["worker"]["sha256"]:
                            matching_worker=True
                    except FileNotFoundError:
                        continue
                if not matching_worker:
                    continue
                return owner,pid,sampled
            return None
        status,pid,active=starter.until(running,220)
        registration=record(BASE/"cadence-registration.json",{
            "schema":"jetstreamer-historical-performance-launch-receipt-v1","kind":"europe-rooted-bank-delta-comparison",
            "epoch":229,"unit":unit,"invocation_id":iid,"main_pid":pid,"node_path":argv[0],"run_root":profile["run_root"],
            "bootstrap_slot":profile["bootstrap_slot"],"first_divergent_slot":profile["divergent_bank_slot"],
            "target_slot":profile["expected_failure_slot"],"terminal_slot":profile["independent_terminal_slot"],
            "launched":True,"entry_replay_requested":True,"canonical_epoch_publication_authorized":False,
            "remote_mutations":False,"r2_mutations":False,"cadence_adapter_installed":False,
            "admission":admission,"guard_plan":plan,"launch_token":token,"active_guard":active,
            "evidence":{"units":[dict(unit=unit,active_state="active",sub_state="running",main_pid=pid,invocation_id=iid,
                restarts=0,result=status["Result"],load_state=status["LoadState"],guarded_binding_verified=True)]},
        })
        print(json.dumps(registration),flush=True)
    except BaseException:
        if not token_released and iid and ops.props(unit,["InvocationID"])["InvocationID"]==iid:
            run("systemctl","stop",unit)
        if not token_released and guard_started:
            run("systemctl","stop",timer,guard)
        raise

def launch(profile,ns,reviewed):
    assert reviewed==PROFILE_SHA
    checked_file(STARTUP,STARTUP_SHA)
    checked_file(TERMINAL292,TERMINAL292_SHA)
    checked_file(PRESTART,PRESTART_SHA)
    sys.dont_write_bytecode=True
    spec=importlib.util.spec_from_file_location("accepted_epoch229_startup",STARTUP)
    kit=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)
    assert os.environ.get("CODEX_THREAD_ID")==kit.replay.THREAD
    with kit.partition.take(),(CONTROL/"cycle.lock").open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK,os.getpid())
        assert kit.ops.props("foundation-publication-cadence-v222.service",["ActiveState","Job"])=={"ActiveState":"inactive","Job":""}
        for name in ("admission.json","guard-plan.json","cadence-registration.json","native-prestart.json","namespace-preflight.json"):
            assert not (BASE/name).exists(),name
        assert not any((BASE/"guard-receipts").iterdir()) and not any(Path(profile["token_root"]).iterdir())
        fit=check()["capacity"]
        assert fit["eligible"] and Path(fit["fleet"]["path"]).parent.name.rsplit("v",1)[-1].isdigit()
        assert int(Path(fit["fleet"]["path"]).parent.name.rsplit("v",1)[-1])>=292
        terminal=json.loads(TERMINAL292.read_text())
        assert terminal["producer"]["MainPID"]==terminal["producer"]["ControlPID"]=="0"
        assert terminal["timer_drained"]=={"ActiveState":"inactive","Job":""}
        prop,argv=kit.startup.start_props(profile["unit"],Path(profile["producer"]["path"]))
        assert argv==profile["argv"]
        for key,value in expected_environment(profile).items():
            assert "--setenv="+key+"="+value in prop,key
        assigned=f"ExecStartPre=/usr/bin/bash {PRESTART} 60 {profile['token_root']}"
        assert assigned in Path(profile["producer"]["path"]).read_text().splitlines()
        prop.append("--property="+assigned)
        inventory=exact_inventory(kit.ops)
        root=Path(profile["filesystem"])
        mountpoint(root)
        setup_namespace(profile,ns)
        selected=[line for line in prop if line.startswith(("--setenv=","--property=ReadWritePaths=",
                 "--property=ReadOnlyPaths=","--property=BindReadOnlyPaths=","--property=ProtectHome=","--property=ProtectSystem="))]
        preflight=json.loads(run("systemd-run","--quiet","--wait","--collect","--pipe",
            "--unit=foundation-229-bank-delta-namespace-v334","--property=Type=exec","--property=User=ubuntu",
            "--property=PrivateNetwork=yes","--property=MemoryMax=1G","--property=MemorySwapMax=0",
            "--property=CPUQuota=100%","--property=TasksMax=32","--property=RuntimeMaxSec=25",
            *selected,"--","/usr/bin/python3","-I","-B","-c",PROBE,probe_payload(profile,ns),timeout=35))
        assert preflight["namespace_verified"] and not preflight["started_replay"]
        namespace=record(BASE/"namespace-preflight.json",dict(profile=ref(BASE/"profile.json"),result=preflight))
        fit=check()["capacity"]
        assert fit["eligible"] and fit["scratch_mount"]=="prepared"
        startup(profile,fit,inventory,namespace,kit,prop)

def main():
    os.umask(0o077)
    assert os.geteuid()==0 and __debug__
    parser=argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check-only",action="store_true")
    modes.add_argument("--namespace-preflight",action="store_true")
    modes.add_argument("--namespace-child",type=int,help=argparse.SUPPRESS)
    modes.add_argument("--launch",action="store_true")
    parser.add_argument("--reviewed-profile-sha256")
    args=parser.parse_args()
    checked_file(BASE/"profile.json",PROFILE_SHA)
    profile=json.loads((BASE/"profile.json").read_text())
    ns=bound(profile["namespace"])
    if args.check_only:
        report=check()
        print(json.dumps(report,indent=2))
        if not report["capacity"]["eligible"]:
            raise SystemExit(2)
    elif args.namespace_preflight:
        print(json.dumps(namespace_preflight(profile,ns),indent=2))
    elif args.namespace_child:
        print(json.dumps(rehearsed_namespace(profile,ns,args.namespace_child),indent=2))
    else:
        launch(profile,ns,args.reviewed_profile_sha256)

if __name__=="__main__":
    main()
