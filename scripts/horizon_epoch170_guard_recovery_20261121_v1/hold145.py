"""Hold only the registered v5 verifier during 170's previously unrecognized Python-join interval."""
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

p=SimpleNamespace(**runpy.run_path(str(Path(__file__).resolve().with_name("profile.py"))))
D=p.D
C=D/"controller-v3"
V=p.R/"epoch145-semantic-continuity-20261121-v1"
U="horizon-holding-export145-20261121-v1.service"
CG=Path("/sys/fs/cgroup/system.slice")
GEN="5e0e20bc974149f096ea4bab10b15e1b"
FAMILY=p.R/"incident-replay-fit-20261121-v1/tools-v4"
SEAL="d1fa7ac39523765c2be3bc3f1870cebba0961595f03308f5d9e771ddbb4144d1"
STATE=D/"holds"
ELAPSED=88

def fields(unit):
    return p.show(unit)

def frozen(unit):
    return dict(l.split() for l in (CG/unit/"cgroup.events").read_text().splitlines())["frozen"]=="1"

def cmd(*args,timeout=7):
    return subprocess.check_output([str(x) for x in args],text=True,timeout=timeout)

def name(iid):
    p.need(re.fullmatch("[0-9a-f]{32}",iid) and int(iid,16),"foreign controller invocation")
    return "horizon-170-verifier-thaw-"+iid

def binding(unit):
    s=fields(unit);pid=int(s["MainPID"]);group=CG/unit
    p.need(s["Id"]==unit and pid>1 and s["ActiveState"]=="active" and s["SubState"]=="running" and
           not s["Job"] and s["ControlPID"]=="0" and s["NRestarts"]=="0","verifier is not stable")
    return dict(unit=unit,invocation=s["InvocationID"],pid=pid,ticks=p.native(pid)[1],cgroup_inode=group.stat().st_ino)

def observed():
    sr=FAMILY/"deployment-seal-receipt.json";seal,_=p.read(sr,SEAL)
    for v in seal["members"]:
        path=FAMILY/v["name"]
        p.need(path.stat().st_uid==0 and not path.stat().st_mode&0o222 and p.digest(path)==v["sha256"],"changed common phase verifier")
    m=runpy.run_path(str(FAMILY/"post-stop-fit"));phase=json.loads(json.dumps(m["phase145"](170)));win=phase["window"]
    p.need(phase["invocation_id"]==GEN and phase["stage"]=="leased-worker" and
           win["native_parent"]==dict(pid=3890323,start_ticks=360965610) and win["native_child"]==dict(pid=3890831,start_ticks=360969081) and
           set(win["leases_parent"])==set(win["leases_worker"])=={"100214429","100214450","103237059"},
           "145 verifier or its six leases changed")
    return phase

def progress(phase):
    win=phase["window"];pid=win["native_child"]["pid"];q=Path(f"/proc/{pid}")
    slots={}
    for ino,f in win["leases_worker"].items():
        p.need((q/"fd"/str(f)).stat().st_ino==int(ino),"145 leased descriptor changed")
        slots[ino]=int(next(l.split()[1] for l in (q/"fdinfo"/str(f)).read_text().splitlines() if l.startswith("pos:")))
    io=dict(l.split(": ",1) for l in (q/"io").read_text().splitlines())
    return dict(offsets=slots,rchar=int(io["rchar"]))

def ready():
    # Outer post::run_child sleeps three seconds between checks. Its stopped-child
    # timeout never runs during this between-checks state.
    ref=binding(U)
    p.need(ref["invocation"]==GEN and ref["pid"]==3890323 and ref["ticks"]==360965610 and not frozen(U),"145 not in its original unfrozen session")
    if p.members(U)!=[3890323,3890831]:return None
    q=Path("/proc/3890323");ch=Path("/proc/3890831")
    child_state=(ch/"stat").read_text().rsplit(")",1)[1].split()[0]
    if child_state not in ("R","S","D") or (q/"syscall").read_text().split()[0]!="230" or (q/"wchan").read_text().strip()!="hrtimer_nanosleep":return None
    return ref

def wait_ready():
    end=time.monotonic()+48
    while time.monotonic()<end:
        before=ready()
        if before:
            try:phase=observed()
            except (ValueError,FileNotFoundError,ProcessLookupError):
                if ready() is None:continue
                raise
            if ready()==before:return before,phase
        time.sleep(.16)
    raise ValueError("no original 145 outer-sleep interval")

def arm(stage,inc,watcher,seconds):
    prefix=name(inc)
    p.need(stage.name==inc and 3<=seconds<=ELAPSED,"wrong bounded thaw interval")
    # Independent timer, separate CPU and memory carved from the controller slot.
    cmd("/usr/bin/systemd-run","--quiet","--collect","--unit="+prefix,"--on-active="+str(seconds)+"s","--timer-property=AccuracySec=150ms",
        "-p","Type=oneshot","-p","TimeoutStartSec=30","-p","CPUQuota=10%","-p","MemoryMax=64M","-p","MemorySwapMax=0",
        "-p","TasksMax=16","-p","NoNewPrivileges=yes","-p","UMask=0077","/usr/bin/python3","-IB",watcher,"deadline",inc)
    timer=fields(prefix+".timer")
    p.need(timer["ActiveState"]=="active" and timer["SubState"]=="waiting" and timer["Triggers"]==prefix+".service","independent thaw timer not armed")
    return timer["InvocationID"]

def same_subject(subject):
    return binding(subject["unit"])==subject

def thaw_subject(stage,subject):
    unit=subject["unit"]
    p.need(same_subject(subject),"refuse to signal a different verifier generation")
    if frozen(unit):cmd("/usr/bin/systemctl","thaw",unit)
    p.need(same_subject(subject) and not frozen(unit),"verifier did not thaw")

def begin():
    inc=os.environ["INVOCATION_ID"];name(inc)
    unit=Path("/proc/self/cgroup").read_text().strip().split("/")[-1]
    p.need(unit.startswith("horizon-170-recovery-start-") and fields(unit)["InvocationID"]==inc,"unregistered 170 controller")
    STATE.mkdir(mode=0o700,exist_ok=True);stage=STATE/inc;stage.mkdir(mode=0o700)
    subject,phase=wait_ready()
    token=dict(subject=subject,phase=phase,controller=unit,controller_iid=inc,controller_pid=os.getpid(),controller_ticks=p.native(os.getpid())[1],
               progress=progress(phase),armed_monotonic=time.monotonic())
    p.record(stage/"INTENT.json",token)
    timer_iid=arm(stage,inc,C/"hold145.py",ELAPSED)
    try:
        p.need(ready()==subject and observed()==phase and ready()==subject,"original verifier left the checked outer sleep")
        # Manager freezes the entire existing cgroup atomically. No actor is killed or restarted.
        cmd("/usr/bin/systemctl","freeze",U)
        p.need(same_subject(subject) and frozen(U) and p.members(U)==[3890323,3890831] and observed()==phase,"different frozen verifier")
        p.need((Path("/proc/3890831/stat").read_text().rsplit(")",1)[1].split()[0]) not in ("T","t","Z"),"verifier had already entered a stopped-child deadline")
        p.record(stage/"HELD.json",dict(subject=subject,timer=timer_iid,phase=phase,progress=progress(phase)))
        return stage
    except BaseException:
        thaw_subject(stage,subject)
        raise

def check(stage):
    token,_=p.read(stage/"INTENT.json");held,_=p.read(stage/"HELD.json")
    timer=fields(name(token["controller_iid"])+".timer")
    p.need(not (stage/"DEADLINE.json").exists() and time.monotonic()-token["armed_monotonic"]<ELAPSED-12 and timer["ActiveState"]=="active" and
           timer["InvocationID"]==held["timer"] and frozen(U) and same_subject(token["subject"]) and observed()==token["phase"],
           "bounded 145 protection changed")

def finish(stage):
    token,_=p.read(stage/"INTENT.json");thaw_subject(stage,token["subject"])
    p.record(stage/"THAWED.json",dict(subject=token["subject"],controller=token["controller_iid"],frozen=False))

def deadline(inc):
    name(inc);stage=STATE/inc;token,_=p.read(stage/"INTENT.json");subject=token["subject"]
    p.need(subject["unit"]==U and subject["invocation"]==GEN and token["controller_iid"]==inc and
           token["controller"].startswith("horizon-170-recovery-start-"),"foreign timed hold")
    if (stage/"THAWED.json").exists():return
    p.record(stage/"DEADLINE.json",dict(controller=inc,subject=subject))
    try:
        # Interrupt only the original controller while its signal handler can unwind.
        cg=fields(token["controller"]);pid=token["controller_pid"]
        if cg["InvocationID"]==inc and int(cg["MainPID"])==pid and p.native(pid)[1]==token["controller_ticks"]:
            fd=os.pidfd_open(pid)
            try:signal.pidfd_send_signal(fd,signal.SIGTERM)
            finally:os.close(fd)
        # The original native 170 protector remains armed. Roll back a still-pending
        # successor only after binding its exact start/exec, and always thaw 145.
        if not (D/"ACTUAL_ADMISSION_AND_PROTECTION.json").exists() and (D/"NATIVE_GATED.json").exists():
            a,_=p.read(D/"NATIVE_GATED.json");state=fields(p.UNIT)
            if state["ActiveState"]=="active" and state["InvocationID"]==a["producer_invocation_id"] and int(state["MainPID"])==a["producer_pid"] and p.native(a["producer_pid"])[1]==a["start_ticks"]:
                cmd("/usr/bin/systemctl","stop","--no-block",p.UNIT)
                end=time.monotonic()+3
                while p.members(p.UNIT) and time.monotonic()<end:time.sleep(.1)
    finally:
        thaw_subject(stage,subject)
        p.record(stage/"TIMED_THAW.json",dict(controller=inc,subject=subject,frozen=False))

if __name__=="__main__":
    p.need(os.geteuid()==0 and sys.flags.isolated and __debug__ and Path(__file__).resolve()==C/"hold145.py","use sealed independent thaw")
    mode,inc=sys.argv[1:];p.need(mode=="deadline","unknown timed mode");deadline(inc)
