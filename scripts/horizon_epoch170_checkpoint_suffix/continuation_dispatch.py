"""Dispatch the read-only comparison, protected actor and enrollment-dependent release."""
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import select
import struct
from pathlib import Path
import subprocess
import sys
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


q = load("continuation_price")
operator = load("bounded_successor")
persist = load("closed_successor").persist


def record(path, doc):
    persist(path,(json.dumps(doc, indent=2)+"\n").encode())
    return q.read(path)[1]


def closed():
    i,_ = q.scope()
    dest = Path(i["closed_comparison"])
    if dest.exists(): return q.compare_predecessor()
    q.predecessor_exit()
    handoff = q.bound(i["closed_terminal_handoff"])
    native = Path(handoff["closed_argv"][0])
    seal = q.bound(handoff["closure_seal"])
    expected = [m for m in seal["members"] if m["name"] == "bounded-checkpoints"]
    q.need(len(expected)==1 and native == Path(seal["destination"])/expected[0]["name"]
           and hashlib.sha256(native.read_bytes()).hexdigest()==expected[0]["sha256"],"changed native checker")
    fit = q.price("read")
    q.need(fit["fits"] and 0 <= time.time()-fit["observed"] < 30,
           "readback capacity (HOME,RAM): "+str((fit["home_margin"],fit["ram_margin"])))
    fit_ref = record(q.DEP/("READ_FIT_"+str(time.time_ns())+".json"),fit)
    q.inactive(q.READ_UNIT)
    start = int(time.time())
    props = ["CPUQuota=100%","MemoryMax=512M","MemorySwapMax=0","TasksMax=16","Nice=8","RuntimeMaxSec=2h",
             "User=root","Group=root","NoNewPrivileges=yes","PrivateNetwork=yes","ProtectSystem=strict",
             "ProtectHome=read-only","PrivateTmp=yes","UMask=0077"]
    args = ["/usr/bin/systemd-run","--quiet","--wait","--pipe","--collect","--service-type=exec","--unit="+q.READ_UNIT]
    for prop in props: args.extend(["--property",prop])
    result = subprocess.run(args+["--",*handoff["closed_argv"]],capture_output=True,timeout=7250)
    q.need(result.returncode == 0, "native comparison failed: "+result.stderr.decode(errors="replace")[-1700:])
    data = json.loads(result.stdout)
    e = data["evidence"]
    q.need(data["release"]==i["old_release"] and data["actor"]==i["old_actor"] and
           [r["slot"] for r in data["checkpoints"]]==[73726716,73746882] and
           e["comparison"]=="closed" and e["pid1_exit"]["native"]["InvocationID"]==q.ORIG
           and len(e["closed_segment"]["sha256"])==64 and not data["canonical_publication_authorized"],
           "different native close result")
    logs = [json.loads(l) for l in q.cmd("/usr/bin/journalctl","-q","--no-pager","-o","json","--since","@"+str(start),
            "_PID=1","_UID=0","UNIT="+q.READ_UNIT,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448").splitlines()]
    q.need(len(logs)==1 and len(logs[0]["INVOCATION_ID"])==32,"no unique successful native reader invocation")
    comparison = record(dest,data)
    record(q.DEP/"CLOSED_READ_ACCEPTANCE.json",dict(comparison=comparison,reader_fit=fit_ref,
           reader_invocation=logs[0]["INVOCATION_ID"],ended=int(time.time()),publication_authorized=False))
    return q.compare_predecessor()


class Changes:
    def __init__(self):
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.fd = self.lib.inotify_init1(os.O_CLOEXEC)
        if self.fd < 0: raise OSError(ctypes.get_errno(), "inotify")
        self.paths = {}

    def watch(self,path):
        wd = self.lib.inotify_add_watch(self.fd,os.fsencode(path),0x100|0x80|0x8)
        if wd < 0: raise OSError(ctypes.get_errno(),"watch "+str(path))
        self.paths[wd] = path

    def events(self,timeout):
        ready,_,_ = select.select([self.fd],[],[],timeout)
        if not ready: return []
        buf = os.read(self.fd,65536)
        pos = 0
        entries = []
        while pos<len(buf):
            wd,mask,_,length = struct.unpack_from("iIII",buf,pos)
            name = os.fsdecode(buf[pos+16:pos+16+length].split(b"\0",1)[0])
            pos += 16+length
            if mask & 0x4000: entries.append(None)
            elif wd in self.paths and name: entries.append(self.paths[wd]/name)
        return entries

    def close(self):
        os.close(self.fd)


def wait_for_guard():
    receipt_dir = Path(q.scope()[0]["guard_receipts"])
    changes = Changes()
    try:
        changes.watch(receipt_dir)
        deadline = time.monotonic()+90
        while not any(receipt_dir.glob("sample-*.json")):
            remaining = deadline-time.monotonic()
            q.need(remaining>0, "held guard did not produce its first sample")
            changes.events(remaining)
    finally: changes.close()


def await_new_fleet(previous_path):
    # The sole existing cadence writes one completed fleet file to each new root
    # directory. Its creation is the only automatic capacity-retry signal.
    changes = Changes()
    try:
        changes.watch(q.RT)
        while True:
            roots = [p for p in q.RT.glob("root*-live*-v*") if p.is_dir()
                     and re.match(r"root[0-9]{6}-",p.name)]
            newest = max(roots,key=lambda p:p.stat().st_mtime_ns)
            changes.watch(newest)
            latest = max(q.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
            if latest != previous_path: return
            for event in changes.events(None):
                if event is None or event.name=="ROOT_COMPLETE_OPERATIONAL_FLEET.json" or (
                        event.parent==q.RT and re.match(r"root[0-9]{6}-",event.name)):
                    break
            else:
                # Discard unrelated directory events without initiating a fleet scan.
                while True:
                    events = changes.events(None)
                    if any(e is None or e.name=="ROOT_COMPLETE_OPERATIONAL_FLEET.json"
                           or (e.parent==q.RT and re.match(r"root[0-9]{6}-",e.name)) for e in events): break
    finally: changes.close()


def dispatch(stage):
    i, ir = q.scope()
    q.need(operator.q.UNIT == q.UNIT and operator.D == q.DEP, "operator is outside its sealed deployment")
    q.need(Path(__file__).resolve().parent == q.DEP/"operator","wrong dispatch executable directory")
    if stage == "check":
        operator.static()
        return {"interface":ir,"wait_for":str(q.DEP/"predecessor-exit/PID1_EXIT.json")}
    closed()
    if stage == "close": return q.compare_predecessor()
    if (q.DEP/"SUCCESSOR_RELEASE.json").exists():
        v,ref=q.read(q.DEP/"SUCCESSOR_RELEASE.json")
        q.need(v["interface"]==ir and q.bound(v["actor"])["unit"]==q.UNIT,"unknown successor release")
        return ref
    if not (q.DEP/"SUCCESSOR_ACTOR.json").exists():
        q.need(stage=="advance","actor is not held")
        operator.start()
    operator.same_actor()
    if not (q.DEP/"ACTUAL_GUARD_PLAN.json").exists():
        q.need(stage=="advance","no actual guard")
        operator.arm()
    if not (q.DEP/"WRITER_ENROLLMENT.json").exists():
        changes = Changes()
        try:
            changes.watch(q.DEP)
            while not (q.DEP/"WRITER_ENROLLMENT.json").exists():
                changes.events(None)
        finally: changes.close()
    wait_for_guard()
    return operator.release()


def main():
    q.need(len(sys.argv)==2 and sys.argv[1] in ("check","close","advance","release"),"select an operational phase")
    stage=sys.argv[1]
    fd=os.open(q.DEP/"bounded-operator.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX)
    try:
        while True:
            basis = max(q.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
            try:
                print(json.dumps(dispatch(stage)),flush=True)
                return
            except Exception as error:
                message = str(error)
                retry = stage in ("advance","release") and any(fragment in message for fragment in
                    (" fit failed: disk ", "readback capacity (HOME,RAM)", "cadence needs its current accepted fleet",
                     "accepted fleet changed during price", "joint postguard HOME coverage failed"))
                record(q.DEP/("DISPATCH_REFUSED_"+str(time.time_ns())+".json"),
                       dict(stage=stage,error=message,observed=int(time.time()),fleet_at_attempt=str(basis),
                            retry_on_new_accepted_fleet=retry,archive_publication_authorized=False))
                if not retry: raise
                await_new_fleet(basis)
    finally: os.close(fd)


if __name__=="__main__": main()
