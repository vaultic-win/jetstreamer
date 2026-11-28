"""Admit the terminal-only private file comparison and publish its exact native output locally."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def load(path):
    spec = importlib.util.spec_from_file_location("successor_price",path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def persist(path, contents):
    tmp = path.with_name("."+path.name+"."+str(os.getpid()))
    fd = os.open(tmp,os.O_RDWR|os.O_NOFOLLOW|os.O_CREAT|os.O_EXCL,0o400)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp,path)
        except FileExistsError:
            if path.read_bytes()!=contents:
                raise ValueError("different existing receipt "+str(path))
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        tmp.unlink()


def main():
    q = load(Path(__file__).with_name("successor_price.py"))
    dep=q.DEP
    program=dep/"bridge-checkpoints-v2/bridge-checkpoints"
    unit="horizon-170-closed-bridge-sha256-20261127-v1.service"
    receipt=dep/"CLOSED_BRIDGE_COMPARISON.json"
    handoff,_=q.read(dep/"bridge-checkpoints-v2/TERMINAL_HANDOFF.json","6aed3dd7dd3dd4aa8715f97cf73e4a01477b2dce683a16d0b3ca876a11694a82")
    q.need(handoff["closed_argv"]==[str(program),"closed"] and hashlib.sha256(program.read_bytes()).hexdigest()
           =="4fd59a7b6a65c85cd9f56d4c094cf4b64499f1472b5a56dcaaf2050df9425e8f","closed checker changed")
    if receipt.exists():
        existing, ref=q.read(receipt)
        q.need(existing["mode"]=="closed" and existing["closed_segment"]["sha256"]
               and existing["release"]==q.scope()[0]["old_release"],"foreign comparison")
        print(json.dumps(ref))
        return
    fit=q.price("closed")
    q.need(fit["fits"] and fit["available_home"]>=fit["required_home"] and fit["available_ram"]>=fit["required_ram"]
           and fit["closed_bridge"] and time.time()-fit["observed"]<10,"insufficient comparison fit: "+str((fit["home_margin"],fit["ram_margin"])))
    fit.update(service=unit,cpu_quota_micros=1000000,memory_max_bytes=512<<20,memory_swap_max_bytes=0,
               archive_scratch_bytes=0,inside_exited_170_booking=True)
    stamp=str(time.time_ns())
    persist(dep/("CLOSED_READ_FIT_"+stamp+".json"),(json.dumps(fit,indent=2)+"\n").encode())
    out=dep/("CLOSED_READ_OUTPUT_"+stamp+".json")
    q.inactive(unit)
    props=["CPUQuota=100%","MemoryMax=512M","MemorySwapMax=0","TasksMax=16","Nice=5","RuntimeMaxSec=2h",
           "Type=exec","User=root","Group=root","NoNewPrivileges=yes","PrivateNetwork=yes","ProtectSystem=strict",
           "ProtectHome=read-only","PrivateTmp=yes","UMask=0077","StandardOutput=file:"+str(out),"StandardError=journal"]
    start=time.time()
    params=["/usr/bin/systemd-run","--wait","--quiet","--unit="+unit]
    for prop in props:
        params.extend(["--property",prop])
    subprocess.run([*params,"--",*handoff["closed_argv"]],check=True,timeout=7300)
    raw=out.read_bytes()
    v=json.loads(raw)
    q.need(v["mode"]=="closed" and v["release"]==q.scope()[0]["old_release"]
           and v["pid1_exit"]["native"]["InvocationID"]==q.ORIG and len(v["checkpoints"])==3
           and v["checkpoints"][-1]["slot"]==73726716 and len(v["closed_segment"]["sha256"])==64
           and v["publication_authorized"] is False, "closed acceptance missing")
    records=[json.loads(l) for l in q.cmd("/usr/bin/journalctl","--no-pager","-q","-o","json","--since","@"+str(int(start)),
                                         "_PID=1","UNIT="+unit,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448").splitlines()]
    q.need(len(records)==1 and len(records[0]["INVOCATION_ID"])==32,"checker has no unique native exit")
    persist(receipt,raw)
    print(json.dumps(q.read(receipt)[1]),flush=True)


if __name__=="__main__":
    main()
