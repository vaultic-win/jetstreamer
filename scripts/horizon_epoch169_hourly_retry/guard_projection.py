"""Qualify the 169 guard's physical tree and worker lookup in its own mount namespace."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time


RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
HOME = Path("/home/sol")
ORIGINAL = HOME / ".jetstreamer-private/epoch169-hourly-source-20261123-v1"
SCRATCH = ORIGINAL / "v158/scratch"
SECOND = RT / "epoch169-hourly-retry-20261128-v2"
GUARD = RT / "epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
GUARD_SHA = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
CONTRACT_SHA = "cc673a4da90aab415f4cf98628492297d0c4b9b713239db24db41e8e89774736"


def contract():
    source = SECOND / "operator-v1/contract.py"
    if hashlib.sha256(source.read_bytes()).hexdigest() != CONTRACT_SHA:
        raise ValueError("different evidence reader")
    return runpy.run_path(str(source))


def show(unit, *fields):
    raw = subprocess.check_output(["/usr/bin/systemctl", "show", "--all", "-p", ",".join(fields), unit], text=True)
    row = dict(line.split("=", 1) for line in raw.splitlines())
    if set(row) != set(fields):
        raise ValueError("incomplete unit observations")
    return row


def run():
    c = contract()
    need = c["need"]
    c["stable"](GUARD, expected=GUARD_SHA, sealed=True)
    closure = c["read"](SECOND / "results/TERMINAL.json", "900841555d64dddb45cec4d0904e90ff8923f22b8f5746f0a54e3bf46874e2ad")[1]
    need(os.geteuid() == 0 and not any(SCRATCH.iterdir()), "old host scratch must be empty")
    fixture = Path(tempfile.mkdtemp(prefix="guard-alias-fixture.", dir=SECOND))
    tree = fixture / "tree"
    reports = fixture / "reports"
    tree.mkdir()
    reports.mkdir()
    marker = tree / "allocated"
    with marker.open("xb") as fd:
        os.posix_fallocate(fd.fileno(), 0, 4 << 20)
        os.fsync(fd.fileno())
    measured = int(subprocess.check_output(["du", "-sx", "-B1", str(tree)], text=True).split()[0])
    unit = f"horizon-qualify-169-alias-fixture-{time.time_ns()}.service"
    executable = SCRATCH / ".historical-runtime/jetstreamer-historical-parent-fixture/bound-worker/historical-worker"
    holder = (
        "import os,sys,shutil;from pathlib import Path;"
        "p=Path(sys.argv[1]);p.parent.mkdir(parents=True,mode=0o700);"
        "shutil.copyfile('/usr/bin/sleep',p);p.chmod(0o700);os.execv(p,[str(p),'100'])"
    )
    options = ["--property=MemoryMax=64M", "--property=MemorySwapMax=0", "--property=CPUQuota=25%",
               "--property=KillMode=control-group", "--property=Restart=no", "--property=PrivateNetwork=yes",
               "--property=ProtectSystem=strict", "--property=ProtectHome=read-only"]
    subprocess.run(["/usr/bin/systemd-run", "--quiet", "--collect", "--service-type=exec", "--unit="+unit,
        "--property=User=sol", "--property=Group=horizon", *options, "--property=RuntimeMaxSec=110s",
        f"--property=TemporaryFileSystem={SCRATCH}:rw,nosuid,nodev,exec,noswap,size=1M,mode=0700,uid=1001,gid=1003",
        "/usr/bin/python3", "-IBc", holder, str(executable)], check=True)
    try:
        owner = show(unit, "InvocationID", "MainPID", "ControlGroup", "ActiveState")
        iid = owner["InvocationID"]
        pid = int(owner["MainPID"])
        proc = Path("/proc") / str(pid)
        until = time.monotonic()+10
        while (proc/"exe").readlink() != executable and time.monotonic() < until:
            time.sleep(.05)
        need(pid>1 and owner["ActiveState"]=="active" and owner["ControlGroup"]=="/system.slice/"+unit
             and (proc/"exe").readlink()==executable and not os.path.lexists(executable)
             and not (proc/"ns/mnt").samefile("/proc/self/ns/mnt"), "fixture worker differs")
        projected = proc/"root"/executable.relative_to("/")
        need(projected.samefile(proc/"exe") and hashlib.sha256(projected.read_bytes()).digest()
             ==hashlib.sha256(Path("/usr/bin/sleep").read_bytes()).digest(), "unexpected fixture image")
        outcomes = {}
        for name, alias, cap, expected in (("original",False,measured+4096,"worker-observation-failed"),
                ("projected",True,measured+4096,None), ("disk",True,measured-1,"root-physical-budget")):
            receipts = reports/name
            receipts.mkdir(mode=0o700)
            plan = dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=unit,invocation_id=iid,
                filesystem=str(HOME),worker_root=str(ORIGINAL if alias else tree),receipt_directory=str(receipts),
                minimum_free_bytes=1,maximum_root_physical_bytes=cap,maximum_worker_vmas=3_500_000)
            ref = c["recorded"](fixture/(name+"-plan.json"),plan)
            probe = f"horizon-169-alias-{name}-{time.time_ns()}"
            args=["/usr/bin/systemd-run","--quiet","--wait","--collect","--service-type=exec","--unit="+probe,*options,
                  "--property=ReadWritePaths="+str(receipts),"--property=User=root","--property=NoNewPrivileges=yes",
                  "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL"]
            if alias:
                args.append(f"--property=BindReadOnlyPaths={tree}:{ORIGINAL}")
            code = subprocess.run([*args,str(GUARD),ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",GUARD_SHA,
                                   "--root-capability-only"],capture_output=True,timeout=15).returncode
            files = list(receipts.glob("root-capability-*.json"))
            need(len(files)==1,"missing native guard evidence for "+name)
            capability,binding=c["read"](files[0],sealed=False)
            sample=capability["sample"]
            need(not capability["producer_signaled"] and not capability["stop_authorized"] and not sample["producer_stop_enabled"]
                 and capability["passed"]==(expected is None) and (code==0)==(expected is None)
                 and sample["producer_invocation_id"]==iid and sample["producer"]["pid"]==pid
                 and sample["guard_sha256"]==GUARD_SHA and sample["plan_sha256"]==ref["sha256"]
                 and sample["trip_reason"]==expected and sample["root_physical_observation_error"] is None,
                 "unexpected native "+name+" guard result: "+str(sample["trip_reason"]))
            physical=sample["root_physical_observation"]
            need(physical["conservative_physical_bytes"]==measured and physical["exceeds_budget"]==(name=="disk"),
                 "physical observation did not measure the fixture's HOME inode")
            if alias:
                need(sample["workers"] and len(sample["workers"])==1 and sample["workers"][0][0]==pid
                     and sample["workers"][0][1]>0 and not sample["worker_observation_error"],"native VMA observation lost")
            else:
                need(sample["workers"]==[] and sample["worker_observation_error"]=="worker escaped the bound generation",
                     "old layout did not reproduce the production failure")
            outcomes[name]=dict(plan=ref,receipt=binding,returncode=code,reason=sample["trip_reason"],workers=sample["workers"],
                                physical_bytes=physical["conservative_physical_bytes"])
        need(show(unit,"InvocationID","MainPID","ActiveState")=={k:owner[k] for k in ("InvocationID","MainPID","ActiveState")},
             "fixture owner changed across checks")
    finally:
        subprocess.run(["/usr/bin/systemctl","stop",unit],check=False)
    need(not (Path("/sys/fs/cgroup/system.slice")/unit/"cgroup.procs").exists() and not os.path.lexists(executable),
         "fixture worker or tmpfs remains")
    # The evidence binds the measured inode and its allocation. The disposable
    # allocation can be unlinked after the three independent scans.
    marker.unlink()
    return c["recorded"](fixture/"COMPLETE.json",dict(schema="horizon-169-guard-layout-fixture-v1",unit=unit,
        invocation=iid,worker_pid=pid,executable=str(executable),original_terminal=closure,guard_sha256=GUARD_SHA,
        physical_source=str(tree),projected_root=str(ORIGINAL),physical_bytes=measured,outcomes=outcomes,
        producer_cleaned=True,fixture_allocation_unlinked=True,archive_publication_authorized=False))


if __name__ == "__main__":
    print(json.dumps(run()))
