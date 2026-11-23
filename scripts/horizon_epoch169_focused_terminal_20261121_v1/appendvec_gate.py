#!/usr/bin/python3 -IB
"""Price and authenticate one G4 scratch transition against the actual focused closure."""
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
import time

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
H = Path("/home/sol/.jetstreamer-private")
BOOK = H / "epoch169-focused-diagnostic-20261117-v1"
OLD = BOOK / "v158/scratch/.historical-runtime/jetstreamer-historical-parent-6hfz7E/jetstreamer-historical-v1.5.8-eHT65K/accounts-state"
CUSTODY = H / "epoch169-g4-appendvec-custody-20261123-v1"
PKG = R / "epoch169-g4-appendvec-20261123-v1/tools-v3"
HELD = CUSTODY / "accounts-state"
P = R / "incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v4"
HOST = R / "epoch166-exact-cargo-retirement-20261123-v1/tools/host.py"
CLOSURE = R / "epoch169-focused-terminal-20261121-v1/closure-tools"
SCREEN = H / "epoch169-hourly-source-20261123-v1/CLOSED_G4_APPENDVECS_SCREEN.json"
HOURLY = H / "epoch169-hourly-source-20261123-v1/HOURLY_SOURCE_AND_TARGET_QA.json"
HOURLY_SHA = "4ea867e664a7676b864df86155493006fe4f5cf282f121974d59006bd0be8544"
BUILD = R / "epoch169-hourly-release-proof-1795425829301762377/HANDOFF.json"
OLD_INODE = 114770421
BYTES = 50285883392
CAP = 96 << 30
BEFORE = 102943473664
TERMINAL = "218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"
DRAIN = "113c410f773cfb565bbed3de95d1c9b7fc17b278010fcae14fa92728a90e1448"
UNIT = "horizon-169-g4-appendvec-"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def price(fleet):
    need(sha(HOST) == "47fdd08d729005893e183ece467a756bcba25b5adccfe3060c1c24829e0c4ece", "foreign fleet selector")
    h = runpy.run_path(str(HOST))
    h["sealed"](P, "ed0e272c1cf6df09bb19ff6049154cad9e55f21e96089f66e6f9e3d0f89da9cb")
    h["sealed"](CLOSURE, "63b5ba5c870820feae7bcbc15b61f2872a0c13b6b3b22295775873cbfab676b3")
    # A long checked/deleting operation may cross cadence. Advance only along the
    # original authenticated five-owner successor chain.
    handoff = P.parent / "tools-homefloor-145-handoff-v1"
    h["sealed"](handoff, "19c0fe27899e6742d095b075377b2adb9aebdb47b2ad2655688b214cd8b632de")
    d = runpy.run_path(str(handoff / "run-recovery"))
    _, initial = d["read"](fleet)
    selected = d["successors"](initial)[-1]
    need(Path(selected["path"]) == h["fleet"](), "not current fleet")
    p = subprocess.run([P / "post-stop-fit", "145", selected["path"], selected["sha256"]], capture_output=True, timeout=168)
    need(p.returncode == 0, p.stderr.decode()[-1600:] or "complete price refused")
    v = json.loads(p.stdout)
    need(v["fleet"] == selected and Path(selected["path"]) == h["fleet"]() and 0 <= time.time()-v["recorded_unix_seconds"] <= 120
         and v["schema"] == "horizon-incident-replay-fit-v1" and v["epoch"] == 145 and v["fits"] and v["resource_credit_bytes"] == 0
         and v["complete_cpu_quota_micros"] == 64000000
         and v["closed_focused169"]["producer_invocation_id"] == "0dfa0d36fbc246c28443a1c90a82c9cb"
         and v["closed_focused169"]["terminal"]["sha256"] == TERMINAL and v["closed_focused169"]["guard_retirement"]["sha256"] == DRAIN,
         "different five-owner price or original terminal")
    return v


def unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def mounts_for(text, dev, source, quarantine):
    for line in text.splitlines():
        fields = line.split()
        need(len(fields) >= 9 and "-" in fields, "incomplete mount record")
        root, point = (Path(unescape(x)) for x in fields[3:5])
        for path in (source, quarantine):
            need(not point.is_relative_to(path), f"mount inside target {point}")
            if fields[2] == dev:
                relative = Path("/") / path.relative_to("/home/sol")
                if root.is_relative_to(relative):
                    raise ValueError(f"mounted original account shard or descendant {root}")
                if relative.is_relative_to(root):
                    need(point / relative.relative_to(root) == path, f"alternate mount path {point}")


def live_namespaces():
    src = OLD.parent
    mount_ids = []
    for path in (src, CUSTODY):
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            need(st.st_dev == 64512 and (path != src or st.st_ino == 114240146), "different source mount")
            mount_ids.append(re.search(r"(?m)^mnt_id:\s*(\d+)$", Path(f"/proc/self/fdinfo/{fd}").read_text())[1])
        finally:
            os.close(fd)
    need(mount_ids[0] == mount_ids[1], "source and quarantine must share a mount for atomic rename")
    namespaces = set()
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal():
            continue
        try:
            key = (p / "ns/mnt").stat().st_ino
            if key in namespaces:
                continue
            content = (p / "mountinfo").read_text()
            need((p / "ns/mnt").stat().st_ino == key, "process changed mount namespace")
            mounts_for(content, "252:0", OLD, HELD)
            namespaces.add(key)
        except (FileNotFoundError, ProcessLookupError):
            continue
    need(namespaces and os.makedev(252, 0) == 64512, "host mount identity changed")
    return len(namespaces)


def readers_between_samples():
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal():
            continue
        try:
            args = [os.fsdecode(x) for x in (p/"cmdline").read_bytes().split(b"\0") if x]
        except (FileNotFoundError, ProcessLookupError):
            continue
        need(not any(Path(x).name == "post-stop-fit" for x in args)
             and not (args and Path(args[0]).name == "du" and str(BOOK) in args),
             "native pricing reader still inside a sample; yield the rename")


def kernel_gate(mode, fleet, step):
    need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and mode in {"qualify","check","execute"}
         and step in {"initial","before-rename","quarantined","settled"}, "unexpected caller")
    need(Path(__file__).resolve() == PKG/"gate.py" and Path(f"/proc/{os.getppid()}/exe").resolve() == PKG/"retire169",
         "only the sealed native owner can enter this gate")
    seal = json.loads((PKG/"deployment-seal-receipt.json").read_bytes())
    need(seal["sealer_sha256"] == SEALER and seal["destination"] == str(PKG) and seal["remote_mutations"] is False, "foreign package")
    for m in seal["members"]:
        p=PKG/m["name"]
        st=p.lstat()
        need(p.resolve(strict=True)==p and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_ISREG(st.st_mode)
             and stat.S_IMODE(st.st_mode)==int(m["mode"],8) and sha(p)==m["sha256"], "changed sealed member")
    name = UNIT + mode + ".service"
    cg = Path("/sys/fs/cgroup/horizonaudit.slice")/name
    need(Path("/proc/self/cgroup").read_text().strip()=="0::/horizonaudit.slice/"+name
         and (cg/"cpu.max").read_text().strip()=="100000 100000" and int((cg/"memory.max").read_text())==805306368
         and int((cg/"memory.swap.max").read_text())==0 and int((cg/"pids.max").read_text())==128, "unpriced helper")
    ns = live_namespaces()
    need(sha(SCREEN)=="b5f5e10ce7453aca40ac5447079eaabe3b99343fef0edab7bd1d4effff05f85a" and sha(HOURLY)==HOURLY_SHA
         and sha(BUILD)=="18ea5efb5b49dc56972c6c725f0e5b12aad029b085ef1a7162cc2077a8a25bb2","different old tree or new source")
    screen = json.loads(SCREEN.read_bytes())
    need(screen["path"]==str(OLD) and screen["root_inode"]==OLD_INODE and screen["candidate"]["allocated_bytes"]==BYTES
         and screen["terminal"]["sha256"]==TERMINAL and screen["drain"]["sha256"]==DRAIN, "changed screened scope")
    v=price(fleet)
    a=runpy.run_path(str(CLOSURE/"closure169.py"))
    terminal=a["committed"]()
    need(terminal["terminal"]==screen["terminal"] and v["closed_focused169"]["live"]==screen["original"],"original exited state changed")
    t=json.loads(Path(screen["terminal"]["path"]).read_bytes())
    need(t["private_output"]==screen["preserved_output"] and t["closed_log"]["inode"]==114704379,"wrong partial or diagnostic log")
    need(sha(Path(t["closed_log"]["path"]))==t["log_sha256"],"diagnostic log changed")
    qstamp=json.loads((PKG/"custody.json").read_bytes())
    q=CUSTODY.lstat()
    need(qstamp==dict(path=str(CUSTODY),device=q.st_dev,inode=q.st_ino) and CUSTODY.resolve(strict=True)==CUSTODY
         and q.st_uid==q.st_gid==0 and q.st_mode==stat.S_IFDIR|0o700,"different quarantine directory")
    if OLD.exists():
        need(not HELD.exists() and OLD.lstat().st_ino==OLD_INODE,"source moved or duplicated")
    elif HELD.exists():
        need(HELD.lstat().st_ino==OLD_INODE,"quarantine replaced")
    else:
        need(step=="settled" or (CUSTODY/"contents-cleared.json").is_file(),"source and quarantine missing without clearance")
    book=v["bookings"]["169"]
    want=BEFORE if OLD.exists() else BEFORE-BYTES
    need(book["root"]==str(BOOK) and book["physical_bytes"]==want and book["remaining_bytes"]==CAP-want and
         book["cap_bytes"]==CAP and book["historical_realized_bytes"]==0 and book["measurement"]=="two complete stopped-tree walks",
         "actual retained booking drifted; reprice the exact closed root")
    # Moving to a sibling on HOME increases the still-reserved growth immediately,
    # before a single physical block is returned. Charge that entire interim liability.
    ledger_growth=0 if (CUSTODY/"checked-ledger.json.zst").exists() else 32<<20
    transient=BYTES if mode=="execute" and OLD.exists() else 0
    need(v["available_HOME_bytes"]-v["complete_required_HOME_bytes"]>=ledger_growth+transient+(1<<20)
         and v["available_memory_bytes"]-v["required_available_memory_bytes"]>=805306368,"insufficient interval capacity")
    if step=="before-rename":
        readers_between_samples()
    return dict(fleet=v["fleet"],terminal=terminal["terminal"],partial=t["private_output"],log=t["closed_log"],booking=book,
                live_mount_namespaces=ns,transient_home_bytes=transient,resource_credit_bytes=0)



def read_only():
    # Kernel file-open and mutation barriers apply to the observer and every
    # descendant. They keep its original ptrace domain for the mandatory host
    # /proc census. The only inherited writable objects are the two output pipes.
    need(stat.S_ISFIFO(os.fstat(0).st_mode) and stat.S_ISFIFO(os.fstat(1).st_mode), "private observer pipes required")
    for candidate in Path("/proc/self/fd").iterdir():
        fd = int(candidate.name)
        if fd <= 2:
            continue
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        except OSError as e:
            if e.errno == errno.EBADF:
                continue
            raise
        need(flags & os.O_ACCMODE == os.O_RDONLY, "unregistered writable observer descriptor")
    sec=ctypes.CDLL("libseccomp.so.2")
    sec.seccomp_init.restype=ctypes.c_void_p
    sec.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p]
    sec.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
    sec.seccomp_load.argtypes=[ctypes.c_void_p]
    sec.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=sec.seccomp_init(0x7fff0000)
    need(ctx,"seccomp init failed")
    class Compare(ctypes.Structure):
        _fields_=[("arg",ctypes.c_uint),("op",ctypes.c_uint),("mask",ctypes.c_uint64),("match",ctypes.c_uint64)]
    def deny(name, comparison=None, error=errno.EPERM):
        nr=sec.seccomp_syscall_resolve_name(name.encode())
        if nr < 0:
            return
        ok=sec.seccomp_rule_add_array(ctx,0x50000|error,nr,int(comparison is not None),
                    None if comparison is None else ctypes.byref(comparison))
        need(ok==0,"seccomp rule failed for "+name+" "+str(ok))
    for name in ("creat truncate ftruncate fallocate unlink unlinkat rename renameat renameat2 mkdir mkdirat rmdir "
                 "link linkat symlink symlinkat chmod fchmod fchmodat fchmodat2 chown fchown lchown fchownat "
                 "mknod mknodat setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr "
                 "utime utimes futimesat utimensat ptrace process_vm_writev pidfd_getfd io_uring_setup "
                 "mount umount2 mount_setattr move_mount open_tree fsopen fsmount fspick fsconfig "
                 "pivot_root setns unshare init_module finit_module delete_module reboot syslog kexec_load "
                 "swapon swapoff open_by_handle_at bpf io_setup io_submit userfaultfd").split():
        deny(name)
    # openat2's flags are behind a userspace pointer. Libraries can fall back
    # to conventional opens, whose flags the kernel filter examines directly.
    deny("openat2",error=errno.ENOSYS)
    for name,arg in (("open",1),("openat",2)):
        for bit in [os.O_WRONLY,os.O_RDWR,os.O_CREAT,os.O_TRUNC,os.O_APPEND,os.O_TMPFILE & ~os.O_DIRECTORY]:
            deny(name,Compare(arg,7,bit,bit))
    need(sec.seccomp_load(ctx)==0, "seccomp load failed")
    sec.seccomp_release(ctx)
    try:
        fd=os.open("/dev/null",os.O_WRONLY)
    except PermissionError as e:
        need(e.errno==errno.EPERM,"unexpected observer denial")
    else:
        os.close(fd)
        raise ValueError("observer can open a writable file")
    need(Path("/proc/1/ns/mnt").stat().st_ino>0 and Path("/proc/1/maps").open("rb").read(1), "host proc inaccessible")


def observe(mode,fleet):
    need(mode in {"check","execute","qualify"} and os.geteuid()==0 and Path(__file__).resolve()==PKG/"gate.py"
         and Path(f"/proc/{os.getppid()}/exe").resolve()==PKG/"retire169","foreign observer owner")
    read_only()
    for line in sys.stdin:
        action=line.rstrip("\n")
        if action=="exit":
            return
        try:
            if action in {"source-readers","held-readers"}:
                run=subprocess.run([PKG/"retire169","scan",action],capture_output=True,timeout=240)
                need(run.returncode==0,run.stderr.decode()[-2000:])
                result=json.loads(run.stdout)
            else:
                result=kernel_gate(mode,fleet,action)
            print(json.dumps(dict(action=action,ok=True,result=result)),flush=True)
        except Exception as e:
            print(json.dumps(dict(action=action,ok=False,error=str(e))),flush=True)
            return

if __name__=="__main__":
    need(len(sys.argv)==4 and sys.argv[1]=="observe","expected observe MODE FLEET")
    observe(sys.argv[2],Path(sys.argv[3]))
