"""Wait for a native guard event and record the first positive transaction marker."""
import ctypes
import os
from pathlib import Path
import re
import select
import stat
import time


MARKER=re.compile(rb"\bjetstreamer_node\] progress slot (\d+)/(\d+) \([^)]*\) txs=(\d+) accounts=(\d+)")


def first_batch(log,scope):
    while True:
        offset=log.tell()
        line=log.readline((1<<20)+1)
        if len(line)>1<<20:
            raise ValueError("oversized 169 producer line")
        if not line.endswith(b"\n"):
            log.seek(offset)
            return None
        match=MARKER.search(line)
        if not match:
            continue
        slot,terminal,txs,updates=map(int,match.groups())
        if terminal!=scope["last"] or not scope["first"]<=slot<=terminal:
            raise ValueError("different private interval marker")
        if slot>scope["first"] and txs>0:
            return dict(slot=slot,terminal=terminal,transactions=txs,account_updates=updates,
                        log_offset=offset,line=line.decode().rstrip())


def follow(owner,scope,sr):
    c=owner["c"]
    grant,gr=c.read(c.CONTROL/"GRANT.json")
    seed,ir=c.read(c.CONTROL/"START_INTENT.json")
    post,pr=c.read(c.CONTROL/"POST_GUARD_PRICE.json",grant["native_post_guard_price_sha256"])
    held,hr=c.read(c.CONTROL/"HELD_GATE.json")
    iid=grant["invocation_id"]
    c.need(held["invocation_id"]==seed["producer_invocation_id"]==iid and seed["scope"]==post["scope"]==sr
           and seed["held"]==hr and seed["guard_plan"]["sha256"]==grant["guard_plan_sha256"]
           and post["fits"] and all(post["postguard_checks"].values()) and not grant["canonical_publication_authorized"],
           "different second attempt release")
    dest=c.CONTROL/"FIRST_PROTECTED_PROGRESS.json"
    if dest.exists():
        existing,ref=c.read(dest)
        c.need(existing["grant"]==gr and existing["intent"]==ir and existing["invocation_id"]==iid,"different first progress")
        return ref
    fleet=c.read(Path(post["whole_roster"]["fleet"]["path"]),post["whole_roster"]["fleet"]["sha256"],sealed=False)[0]
    pid=grant["pid"]
    proc=Path("/proc")/str(pid)
    logpath=Path(scope["log"])
    receipts=c.RETRY/"hourly-guard-receipts"
    libc=ctypes.CDLL(None,use_errno=True)
    fd=libc.inotify_init1(os.O_CLOEXEC)
    if fd<0:
        raise OSError(ctypes.get_errno(),"guard notification")
    try:
        if libc.inotify_add_watch(fd,os.fsencode(receipts),0x100|0x80|0x8)<0:
            raise OSError(ctypes.get_errno(),"guard receipt directory")
        pidfd=os.pidfd_open(pid)
        try:
            with logpath.open("rb") as log:
                st=os.fstat(log.fileno())
                c.need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and (st.st_dev,st.st_ino)==(grant["log_device"],grant["log_inode"])
                       and (proc/"fd/1").samefile(logpath) and (proc/"fd/2").samefile(logpath),"foreign producer log")
                until=time.monotonic()+75*60
                batch=None
                while True:
                    batch=batch or first_batch(log,scope)
                    if batch:
                        row=owner["observe"].current(fleet)
                        c.need(row and row["invocation_id"]==iid and row["phase"] in ("bootstrap","worker")
                               and row["release"]==gr and row["guard_plan"]==seed["guard_plan"],"worker changed at first progress")
                        if row["phase"]=="worker":
                            c.need((proc/"fd/1").samefile(logpath) and os.path.samestat(st,logpath.stat())
                                   and not select.select([pidfd],[],[],0)[0],"producer exited across progress")
                            return c.recorded(dest,dict(schema="horizon-169-second-first-guarded-progress-v1",
                                recorded_unix=time.time(),scope=sr,grant=gr,intent=ir,postguard=pr,invocation_id=iid,
                                producer_pid=pid,worker=row["worker"],guard=row["guard"],guard_plan=row["guard_plan"],progress=batch,
                                log_inode=st.st_ino,log_device=st.st_dev,canonical_publication_authorized=False))
                    left=until-time.monotonic()
                    c.need(left>0,"first worker progress expired")
                    ready,_,_=select.select([fd,pidfd],[],[],left)
                    c.need(ready and pidfd not in ready,"producer exited or first progress expired")
                    os.read(fd,65536)
        finally:
            os.close(pidfd)
    finally:
        os.close(fd)
