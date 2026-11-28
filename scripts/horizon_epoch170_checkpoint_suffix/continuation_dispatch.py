"""Dispatch the read-only comparison, protected actor and enrollment-dependent release."""
from contextlib import contextmanager, nullcontext
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


def following_checker():
    capture, _ = q.read(q.DEP / "PREDECESSOR_CAPTURE_ACTIVE.json",
                        "1f84466d9ec0697cd1b2e4c367f557ec63370935af882ef5d4d5379fd5082920")
    armed = q.bound(capture["armed"])
    old = q.close_interface()
    q.need(capture["predecessor"] == armed["release"] == old["old_release"]
           and armed["actor"] == q.bound(old["old_actor"]) and armed["pidfd_bound"] and armed["unit_reference_held"],
           "previous exit observer differs from the sealed actor")
    return {"closure_seal":capture["capability"], "closed_argv":[str(q.DEP/"closure-tools"/q.CHECKER), "closed"]}


def closed():
    i = q.close_interface()
    dest = Path(i["closed_comparison"])
    if dest.exists(): return q.compare_predecessor()
    q.predecessor_exit()
    handoff = following_checker() if q.FOLLOWING else q.bound(i["closed_terminal_handoff"])
    native = Path(handoff["closed_argv"][0])
    seal = q.bound(handoff["closure_seal"])
    expected = [m for m in seal["members"] if m["name"] == q.CHECKER]
    q.need(len(expected)==1 and native == Path(seal["destination"])/expected[0]["name"]
           and hashlib.sha256(native.read_bytes()).hexdigest()==expected[0]["sha256"],"changed native checker")
    with admission_lock() if q.FOLLOWING else nullcontext():
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
        child = subprocess.Popen(args+["--",*handoff["closed_argv"]],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        reader_id = None
        if q.FOLLOWING:
            # Keep the admission lock through activation; release it for the
            # complete segment readback once the native caps and PID are visible.
            for _ in range(100):
                row = q.state(q.READ_UNIT)
                if row["ActiveState"] == "active":
                    q.need(row["MemoryMax"] == str(512<<20) and row["MemorySwapMax"] == "0"
                           and row["CPUQuotaPerSecUSec"] == "1s" and len(row["InvocationID"]) == 32
                           and (Path("/proc")/row["MainPID"]/"exe").samefile(native),
                           "foreign native closed reader")
                    reader_id = row["InvocationID"]
                    break
                if child.poll() is not None:
                    break
                time.sleep(.05)
            q.need(reader_id or child.poll() is not None, "native closed reader did not start")
    try:
        out, err = child.communicate(timeout=7250)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise
    q.need(child.returncode == 0, "native comparison failed: "+err.decode(errors="replace")[-1700:])
    data = json.loads(out)
    e = data["evidence"]
    q.need(data["release"]==i["old_release"] and data["actor"]==i["old_actor"] and
           [r["slot"] for r in data["checkpoints"]]==q.PREVIOUS_SLOTS and
           e["comparison"]=="closed" and e["pid1_exit"]["native"]["InvocationID"]==q.ORIG
           and len(e["closed_segment"]["sha256"])==64 and not data["canonical_publication_authorized"],
           "different native close result")
    logs = [json.loads(l) for l in q.cmd("/usr/bin/journalctl","-q","--no-pager","-o","json","--since","@"+str(start),
            "_PID=1","_UID=0","UNIT="+q.READ_UNIT,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448").splitlines()]
    q.need(len(logs)==1 and len(logs[0]["INVOCATION_ID"])==32,"no unique successful native reader invocation")
    q.need(not reader_id or reader_id == logs[0]["INVOCATION_ID"], "native reader invocation changed")
    if q.FOLLOWING:
        signatures = e["signed_checkpoints"]
        q.need([q.bound(r)["slot"] for r in signatures] == q.PREVIOUS_SLOTS and e["signed_endpoint"] == signatures[-1],
               "closed result lacks all four confirmed vote identities")
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


@contextmanager
def admission_lock():
    # Serialize each resource mutation with the 143 booker/operator. Release the
    # host lock while awaiting the existing guard, writer and cadence events.
    with Path("/run/horizon-epoch171-to136-g1.operation.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def enrollment_writer(interface, ref):
    base = q.RT/"survivor172-cadence-20261122-v1"
    if q.OPERATOR in operator.ENROLLING_OPERATORS:
        version = 47
        binding, _ = q.read(q.OPERATOR/"binding.json")
        expected = binding["writer_active"]
        q.need(expected["path"] == str(base/"FAILED166_CADENCE_V47_ACTIVE.json"), "different fourth-window writer")
        active = q.bound(expected)
        versions = (48,49) if q.OPERATOR == operator.SPLIT_FOLLOWING else (48,) if q.OPERATOR == operator.RECONCILED_FOLLOWING else ()
        if q.OPERATOR == operator.CHAIN_FOLLOWING:
            versions = load("following_peers").writer_versions(base,48)
        for successor_version in versions:
            successor = base / f"FAILED166_CADENCE_V{successor_version}_ACTIVE.json"
            if not successor.exists():
                break
            next_active, next_ref = q.read(successor)
            ready = q.bound(next_active["ready"])
            q.need(ready["old_owner"] == expected and next_active["old"] == active["new"]
                   and next_active["new"]["unit"] == active["new"]["unit"]
                   and all(next_active["new"]["lock"][k] == active["new"]["lock"][k] for k in ("path", "device", "inode")),
                   f"V{successor_version} did not inherit the previous writer and its cadence lock")
            active, expected, version = next_active, next_ref, successor_version
        if q.OPERATOR in (operator.SPLIT_FOLLOWING,operator.CHAIN_FOLLOWING):
            q.need(version >= 48, "missing split-actor writer")
        prior_interface = q.bound(interface["old_release"])["interface"]
    else:
        q.need(q.RETRY, "this operator has no writer enrollment command")
        version = 46
        active, _ = q.read(base/"FAILED166_CADENCE_V46_ACTIVE.json")
        prior_interface = interface["previous_interface"]
    writer = active["new"]
    state = q.state(writer["unit"])
    ready = q.bound(active["ready"])
    program = Path(writer["program"])
    seal = q.bound(ready["package"])
    member, = (m for m in seal["members"] if m["name"] == program.name)
    q.need(active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1" and not active["producer_mutations"]
           and ready["successor170_interface"] == ref and ready["prior_successor170_interface"] == prior_interface
           and program.name == "status_cycle.py" and program.parent.parent == base
           and re.fullmatch(rf"tools-cold168-retry5-failed166-v{version}-entry146(?:-r[1-9][0-9]*)?", program.parent.name)
           and program.resolve(strict=True) == program and seal["destination"] == str(program.parent)
           and ready["package"]["path"] == str(program.parent/"deployment-seal-receipt.json")
           and operator.digest(program) == member["sha256"] and state["ActiveState"] == "active"
           and state["InvocationID"] == writer["invocation_id"] and state["MainPID"] == str(writer["pid"])
           and int((Path("/proc")/str(writer["pid"])/"stat").read_text().rsplit(") ",1)[1].split()[19]) == writer["start_ticks"],
           "active writer has not accepted this bounded interface")
    return program


def dispatch(stage):
    if stage == "check-capture":
        q.need(q.FOLLOWING, "capture check requires its following-window reader")
    if q.FOLLOWING and stage in ("check-capture", "close"):
        deployment = Path(__file__).resolve().parent
        q.need(deployment in operator.FOLLOWING_READERS | operator.ENROLLING_OPERATORS | {operator.FOLLOWING_DEPLOYMENT}
               and q.DEP == operator.D and q.UNIT == operator.q.UNIT, "unbound following checker")
        if stage == "check-capture":
            return following_checker()
        closed()
        return q.compare_predecessor()
    i, ir = q.scope()
    q.need(operator.q.UNIT == q.UNIT and operator.D == q.DEP, "operator is outside its sealed deployment")
    deployment = Path(__file__).resolve().parent
    allowed = operator.RETRY_OPERATORS if q.RETRY else operator.CONTINUATIONS
    q.need(deployment in allowed and deployment.parent == q.DEP, "wrong dispatch executable directory")
    if stage == "check":
        operator.static()
        return {"interface":ir,"predecessor_exit":q.predecessor_exit()}
    closed()
    if stage == "close": return q.compare_predecessor()
    if (q.DEP/"SUCCESSOR_RELEASE.json").exists():
        v,ref=q.read(q.DEP/"SUCCESSOR_RELEASE.json")
        q.need(v["interface"]==ir and q.bound(v["actor"])["unit"]==q.UNIT,"unknown successor release")
        return ref
    enroll = q.RETRY or deployment in operator.ENROLLING_OPERATORS
    if enroll:
        enrollment_writer(i, ir)
    if not (q.DEP/"SUCCESSOR_ACTOR.json").exists():
        q.need(stage=="advance","actor is not held")
        with admission_lock():
            operator.start()
    operator.same_actor()
    if not (q.DEP/"ACTUAL_GUARD_PLAN.json").exists():
        q.need(stage=="advance","no actual guard")
        with admission_lock():
            operator.arm()
    if enroll and not (q.DEP/"WRITER_ENROLLMENT.json").exists():
        wait_for_guard()
        with admission_lock():
            operator.guard()
            command = enrollment_writer(i, ir)
            _, head = q.prior.current_fleet()
            subprocess.run(["/usr/bin/python3", "-IB", str(command), "--enroll-next-bounded-170",
                            head["path"], head["sha256"]], check=True, timeout=70)
            q.need((q.DEP/"WRITER_ENROLLMENT.json").is_file(), "writer returned without an enrollment")
    if not (q.DEP/"WRITER_ENROLLMENT.json").exists():
        changes = Changes()
        try:
            changes.watch(q.DEP)
            while not (q.DEP/"WRITER_ENROLLMENT.json").exists():
                changes.events(None)
        finally: changes.close()
    wait_for_guard()
    with admission_lock():
        return operator.release()


def main():
    q.need(len(sys.argv)==2 and sys.argv[1] in ("check","check-capture","close","advance","release"),"select an operational phase")
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
                retry = (stage in ("advance","release") or (q.FOLLOWING and stage == "close")) and any(fragment in message for fragment in
                    (" fit failed: disk ", "readback capacity (HOME,RAM)", "cadence needs its current accepted fleet",
                     "accepted fleet changed during price", "joint postguard HOME coverage failed",
                     "changed during the fourth-window quote", "private listener is in transition",
                     "private scanner is in transition"))
                record(q.DEP/("DISPATCH_REFUSED_"+str(time.time_ns())+".json"),
                       dict(stage=stage,error=message,observed=int(time.time()),fleet_at_attempt=str(basis),
                            retry_on_new_accepted_fleet=retry,archive_publication_authorized=False))
                if not retry: raise
                if (q.RETRY or q.OPERATOR in operator.ENROLLING_OPERATORS) and (q.DEP/"SUCCESSOR_ACTOR.json").exists():
                    operator.same_actor()
                    # The native pre-release gate expires in ten minutes; reprice within its lifetime.
                    time.sleep(20)
                else:
                    await_new_fleet(basis)
    finally: os.close(fd)


if __name__=="__main__": main()
