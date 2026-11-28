"""Verify the recovered local commit and retire its original periodic guard after PID 1 exit."""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from typing import NamedTuple

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
T = R / "epoch166-retry10-terminal-20261121-v1"
D = R / "epoch166-independent-cold-recovery-20261121-v1"
FIELD = "recovered166_local_commit"
IID = "3c220efd0d0740f59572a96447e83762"
UNIT = "horizon-qualify-166-independent-recovery-20261121-v1.service"
TIMER = "horizon-guard-166-independent-recovery-20261121-v1.timer"
GUARD = TIMER.removesuffix(".timer") + ".service"
TIMER_IID = "a7da9f28946a4cdbbed029f26d79f2e7"
ELF = "a0b16335629102b6003eb86a61aef4e9bcc7263dc6a35863897d4d326bdb81f3"
LIVE = "d560fdc80612b6654a68c57470a26b77bd98535c30068c9008e6b70fa032165e"
AD = "28da473912ec78836cc0329be99d1a269dd4994d1b78f2fa619d344196e420cd"
WORKER = "19ed8279aaf1e85bdadae6974d2d1c6f1d1c019a122d7bad5d26259c9d3eb4aa"
INTENT = T / "TERMINAL_GUARD_RETIRE_INTENT.json"
DONE = T / "TERMINAL_GUARD_DRAINED.json"

def need(ok, why):
    if not ok:
        raise ValueError(why)

def member(path, mode, expected=None, limit=4<<20):
    need(path.is_absolute() and path.resolve(strict=True)==path, "noncanonical receipt")
    with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as src:
        m=os.fstat(src.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==m.st_gid==0 and m.st_nlink==1 and
             stat.S_IMODE(m.st_mode)==mode and 0<m.st_size<=limit,"changed root file "+str(path))
        raw=src.read(limit+1)
        need(len(raw)==m.st_size and m.st_ctime_ns==os.fstat(src.fileno()).st_ctime_ns and
             os.path.samestat(m,path.lstat()),"member changed")
    ref=dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest())
    need(expected is None or ref["sha256"]==expected,"incorrect digest "+str(path))
    return raw,ref

def document(path, mode, expected=None):
    raw,ref=member(path,mode,expected)
    return json.loads(raw),ref

def once(path,body):
    raw=(json.dumps(body,sort_keys=True,indent=2)+"\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as f:
        try:
            os.fchmod(f.fileno(),0o400);f.write(raw);f.flush();os.fsync(f.fileno())
            rename=ctypes.CDLL(None,use_errno=True).renameat2
            if rename(-100,os.fsencode(f.name),-100,os.fsencode(path),1):
                error=ctypes.get_errno()
                if error!=errno.EEXIST:raise OSError(error,"commit "+str(path))
        finally:
            Path(f.name).unlink(missing_ok=True)
    target,ref=document(path,0o400)
    need(target==body,"conflicting guard retirement record")
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return ref

def manager(name):
    fields="Id,LoadState,InvocationID,ActiveState,SubState,MainPID,ControlPID,Job,Triggers"
    result=subprocess.run(["/usr/bin/systemctl","show","-p",fields,name],capture_output=True,text=True,timeout=12)
    row=dict(l.split("=",1) for l in result.stdout.splitlines())
    need(row.get("Id")==name and (result.returncode==0 or result.returncode==4 and row["LoadState"]=="not-found"),"missing manager state")
    return row

def drained(name):
    row=manager(name)
    group=Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs"
    need(row["ActiveState"] in ("inactive","failed") and not row["Job"] and
         all(row.get(k,"0") in ("","0") for k in ("MainPID","ControlPID")) and
         not (group.exists() and group.read_bytes().strip()), "guard still occupied "+name)
    return row

class GuardClosure(NamedTuple):
    epoch: int
    terminal_root: Path
    admission_root: Path
    producer_unit: str
    producer_id: str
    guard_timer: str
    guard_timer_id: str
    witness_hash: str
    admission_hash: str
    admission_mode: int
    worker_hash: str
    terminal_program_hash: str
    worker_mode: int = 0o444
    witness_mode: int = 0o600

    @property
    def guard_service(self):
        return self.guard_timer.removesuffix(".timer") + ".service"

    @property
    def intent_path(self):
        return self.terminal_root / "TERMINAL_GUARD_RETIRE_INTENT.json"

    @property
    def completion_path(self):
        return self.terminal_root / "TERMINAL_GUARD_DRAINED.json"

    def validate_terminal(self,t,live,lr,ar,wr):
        boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        event=t["manager_terminal"]
        need(live["boot_id"]==boot and t["schema"]==f"terminal{self.epoch}-success-v1" and t["epoch"]==self.epoch and
             t["live"]==lr and t["source_admission"]==live["admission"]==ar and live["first_protected_worker"]==wr and
             t["producer_unit"]==self.producer_unit and t["producer_invocation_id"]==self.producer_id and
             t[f"terminal_{self.epoch}_disposition"]=="node-published-local-cohort" and
             t["resource_credit_bytes"]==t["reservation_ending_bytes"]==0 and
             all(t[k] is False for k in ("archive_publication_authorized","new_producer_authorized","canonical_r2_verified")) and
             event["_PID"]=="1" and event["_BOOT_ID"]==boot.replace("-","") and event["UNIT"]==self.producer_unit and
             event["INVOCATION_ID"]==self.producer_id and event["MESSAGE_ID"]=="7ad2d189f7e94e70a38c781354912448",
             f"different epoch {self.epoch} terminal")

    def committed(self):
        term,tr=document(self.terminal_root/"TERMINAL_SUCCESS.json",0o400)
        live,lr=document(self.terminal_root/"LIVE.json",self.witness_mode,self.witness_hash)
        a,ar=document(self.admission_root/"ACTUAL_ADMISSION_AND_PROTECTION.json",self.admission_mode,self.admission_hash)
        w,wr=document(self.admission_root/"FIRST_PROTECTED_WORKER.json",self.worker_mode,self.worker_hash)
        self.validate_terminal(term,live,lr,ar,wr)
        need(a["producer_unit"]==self.producer_unit and a["producer_invocation_id"]==self.producer_id and a["timer_unit"]==self.guard_timer and
             a["timer_invocation_id"]==self.guard_timer_id and w["admission"]==ar,"foreign admitted guard")
        tool=self.terminal_root/f"terminal-tools/terminal{self.epoch}"
        member(tool,0o555,self.terminal_program_hash,8<<20)
        same=json.loads(subprocess.check_output([tool,"inspect"],timeout=45))
        need(same==term and not any((self.admission_root/"guard-receipts").glob("stop-*.json")),
             "native original commit changed or guard stopped producer")
        return dict(terminal=tr,admission=ar,first_worker=wr,live=lr,producer_invocation_id=self.producer_id,
                    timer_unit=self.guard_timer,timer_invocation_id=self.guard_timer_id,guard_unit=self.guard_service,resource_credit_bytes=0)

    def expected_timer(self,t):
        need(t["Id"]==self.guard_timer and t["ActiveState"]=="active" and t["InvocationID"]==self.guard_timer_id
             and t["Triggers"]==self.guard_service and not t["Job"],"foreign recovered guard timer")

    def inspect(self):
        evidence=self.committed()
        intent,ir=document(self.intent_path,0o400)
        done,dr=document(self.completion_path,0o400)
        need(intent["binding"]==evidence and done["intent"]==ir and done["binding"]==evidence,
             "foreign terminal guard retirement")
        self.expected_timer(intent["before"])
        drained(self.guard_timer);drained(self.guard_service)
        return dict(evidence,guard_retirement=dr)

    def retire(self):
        need(os.geteuid()==0,"retirement requires root")
        with (self.terminal_root/"terminal-guard-retirement.lock").open("a+b") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if self.completion_path.exists():return self.inspect()
            binding=self.committed()
            if self.intent_path.exists():
                intent,ir=document(self.intent_path,0o400)
                need(intent["binding"]==binding,"terminal changed after intent")
                self.expected_timer(intent["before"])
            else:
                before=manager(self.guard_timer);self.expected_timer(before)
                ir=once(self.intent_path,dict(binding=binding,before=before))
            current=manager(self.guard_timer)
            if current["ActiveState"]=="active":
                self.expected_timer(current)
                subprocess.run(["/usr/bin/systemctl","stop",self.guard_timer],check=True,timeout=25)
            deadline=time.monotonic()+125
            while True:
                try:
                    after=[drained(self.guard_timer),drained(self.guard_service)]
                    break
                except ValueError:
                    if time.monotonic()>=deadline:raise
                    time.sleep(.5)
            need(binding==self.committed(),"terminal changed during guard retirement")
            once(self.completion_path,dict(binding=binding,intent=ir,after=after))
            return self.inspect()


ORIGINAL = GuardClosure(166, T, D, UNIT, IID, TIMER, TIMER_IID, LIVE, AD, 0o444, WORKER, ELF)
validate_terminal = ORIGINAL.validate_terminal
committed = ORIGINAL.committed
expected_timer = ORIGINAL.expected_timer
inspect = ORIGINAL.inspect
retire = ORIGINAL.retire

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=["inspect","retire"])
    profile = parser.add_mutually_exclusive_group()
    for name in ("cold167", "cold170"):
        profile.add_argument("--" + name, dest="producer", action="store_const", const=name)
    args = parser.parse_args()
    guard = ORIGINAL
    if args.producer:
        import runpy
        peers = runpy.run_path(str(Path(__file__).with_name("peer_closures.py")))
        guard = peers[args.producer]().guard
    print(json.dumps(guard.retire() if args.action == "retire" else guard.inspect(), sort_keys=True))
