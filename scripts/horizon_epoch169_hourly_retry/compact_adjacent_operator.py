"""Qualify a 48 GiB adjacent 169 producer on the original unit, guard and immutable inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_inputs as a
from derive_adjacent_writer import INTERFACE as OLD_INTERFACE

ROOT=a.BASE
OLD=ROOT/"operator-v1"
PKG=ROOT/"operator-48-v1"
SCOPE=ROOT/"SCOPE_48.json"
INTERFACE=ROOT/"INTERFACE_48.json"
PRIOR_PRICE=a.RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v33"
V33=dict(path=str(PRIOR_PRICE/"deployment-seal-receipt.json"),sha256="1038dea831483b370de8991b3093d958a2e5613615bda92ee6709ddc1d48ec5f")
PEAK=dict(path=str(ROOT/"PREDECESSOR_KERNEL_PEAK.json"),sha256="c7e3b563b998c01fbad4c2d942bb1ca0d87506610a6234a44160578dd7541886")
REFUSAL=dict(path=str(ROOT/"ADJACENT_PRESTART_PRICE_1795865026772519147.json"),sha256="8a104324f97db3ed9fdd0df81be18dbbca55a13c977444d3403ed625e5d3806d")
G=1<<30
LIMIT=48*G
one=a.shared.exact


def original():
    info=a.bind(OLD_INTERFACE)
    seal=a.bind(info["provider"])
    a.need(seal["destination"]==str(OLD) and info["unit"]==a.UNIT and info["field"]==a.FIELD,"unknown original operator")
    for m in seal["members"]:
        p=OLD/m["name"]
        st=p.lstat()
        a.need(p.parent==OLD and p.resolve(strict=True)==p and st.st_uid==0 and st.st_nlink==1
               and not st.st_mode & 0o222 and a.digest(p)==m["sha256"],"changed original operator member")
    return info,runpy.run_path(str(OLD/"layout.py"))


def evidence():
    info,layout=original()
    model=layout["scope"]()
    peak=a.bind(PEAK)
    fields=peak["kernel_fields"]
    source=subprocess.check_output(["journalctl","--no-pager","-q","-o","json","_PID=1","_UID=0",
        "INVOCATION_ID="+a.OLD_IID,"UNIT="+fields["UNIT"],"MESSAGE_ID=ae8f7b866b0347b9af31fe1c80b127c0"])
    row,=map(json.loads,source.splitlines())
    old=a.bind(model["previous_scope"])
    refused=a.bind(REFUSAL)
    a.need(all(row[k]==v for k,v in fields.items()) and fields["MEMORY_PEAK"]=="40728358912" and fields["MEMORY_SWAP_PEAK"]=="0"
           and peak["predecessor"]==model["previous"] and peak["next_scope"]==info["scope"] and peak["prior_scope"]==model["previous_scope"]
           and old["last"]+1==model["first_slot"] and model["position_count"]==7025 and old["position_count"]==6778
           and old["quota"]==model["quota"] and old["quota"]["producer_ram"]==56*G and old["quota"]["scratch"]==44*G
           and LIMIT-int(fields["MEMORY_PEAK"])==peak["positive_headroom_over_predecessor"]==10811248640
           and not refused["fits"] and refused["phase"]=="prestart" and refused["held_invocation"] is None
           and refused["home_margin"]==9038649804 and refused["ram_margin"]==-3951080448
           and refused["whole_roster"]["package"]==V33 and not refused["whole_roster"]["adjacent_169_accounting"]["enrollment"],
           "unrecognized peak, V33 refusal or Bank span")
    layout["sources"]()
    return info,model,layout


def not_issued(layout):
    for n in ("UNIT","TIMER"):
        props=layout["manager"](layout[n])
        a.need(props["ActiveState"] in ("inactive","failed") and props.get("MainPID","0")=="0"
               and not props["Job"] and not props.get("ControlGroup"),"original 169 reservation is occupied")
    guard=layout["manager"](layout["TIMER"].replace(".timer",".service"))
    a.need(guard["ActiveState"] in ("inactive","failed") and guard["MainPID"]=="0" and not guard["Job"]
           and not guard["ControlGroup"] and all(not os.path.lexists(p) for p in
           (ROOT/"ADJACENT169_ENROLLMENT.json",layout["DATA"],layout["GUARDS"],layout["ALLOW"],layout["RUN"],layout["CGROUP"])),
           "original 169 already enrolled or retained state")


def files(model_hash):
    info,layout=original()
    result={}
    for m in a.bind(info["provider"])["members"]:
        n=m["name"]
        if not n.endswith(".py"):
            continue
        body=(OLD/n).read_text()
        if n=="layout.py":
            for old,new in (('PKG = BASE / "operator-v1"','PKG = BASE / "operator-48-v1"'),
                            ('HANDOFF = BASE / "SCOPE.json"','HANDOFF = BASE / "SCOPE_48.json"'),
                            (info["scope"]["sha256"],model_hash),("worker_anonymous_allowance=12 * G","worker_anonymous_allowance=4 * G"),
                            ("(scratch_gib + 12) * G","(scratch_gib + 4) * G"),("(scratch_gib + 13) * G","(scratch_gib + 5) * G")):
                body=one(body,old,new)
        if n=="status169.py":
            body=one(body,str(OLD),str(PKG))
        if n=="close.py":
            body=one(body,"56-GiB/2-CPU","48-GiB/2-CPU")
        compile(body,n,"exec")
        result[n]=body.encode()
    return result


def fixture(layout,model):
    original_plan=layout["profile"](44)
    ns={"__name__":"check_reduced_layout"}
    exec(files("0"*64)["layout.py"],ns)
    target=ns["profile"](44)
    expected=dict(original_plan,producer_memory_max=LIMIT,combined_ram=LIMIT+G,worker_anonymous_allowance=4*G)
    a.need(target==expected and ns["PKG"]==PKG and ns["HANDOFF"]==SCOPE,"unbounded change to the 169 profile")
    args=ns["producer_argv"](44,model,model["profile"]["readonly_projections"])
    old=layout["producer_argv"](44,model,model["profile"]["readonly_projections"])
    expected={f"--property=MemoryMax={56*G}":f"--property=MemoryMax={LIMIT}",f"--property=MemoryHigh={53*G}":f"--property=MemoryHigh={45*G}"}
    a.need(args==[expected.get(arg,arg) for arg in old] and set(expected)<=set(old)
           and ns["guard_plan"]("1"*32,ns["MIN_FLOOR"])==layout["guard_plan"]("1"*32,layout["MIN_FLOOR"]),
           "producer binding, guard or argv changed outside the qualified memory limits")
    native=runpy.run_path(str(OLD/"terminal_bank.py"))["fixture"]()
    return target,native


def kernel_fixture(layout):
    unit="horizon-169-48g-cap-fixture-"+str(time.time_ns())+".service"
    cgroup=Path("/sys/fs/cgroup/system.slice")/unit
    args=["/usr/bin/systemd-run","--quiet","--wait","--pipe","--collect","--unit="+unit,
          "--property=User=sol","--property=MemoryMax="+str(LIMIT),"--property=MemoryHigh="+str(LIMIT-3*G),
          "--property=MemorySwapMax=0","--property=CPUQuota=200%","--property=TasksMax=1","--property=LimitAS=32M",
          "--property=RuntimeMaxSec=15","--property=ProtectSystem=strict","--property=ProtectHome=yes",
          "--property=NoNewPrivileges=yes","--property=PrivateNetwork=yes","--","/usr/bin/cat",
          *(str(cgroup/f) for f in ("memory.max","memory.high","memory.swap.max","cpu.max"))]
    p=subprocess.run(args,capture_output=True,text=True,check=True,timeout=25)
    values=p.stdout.strip().splitlines()
    a.need(values==[str(LIMIT),str(LIMIT-3*G),"0","200000 100000"] and not cgroup.exists(),"kernel cap fixture did not drain")
    return dict(unit=unit,argv=args,kernel_values=values,exit_status=p.returncode)


def published(revision,paths):
    repo=HERE.parents[1]
    git=["git","-c","safe.directory="+str(repo),"-C",str(repo)]
    subprocess.run([*git,"merge-base","--is-ancestor",revision,"origin/account-updates"],check=True)
    for p in paths:
        a.need(subprocess.check_output([*git,"show",revision+":"+str(p.relative_to(repo))])==p.read_bytes(),"unpublished "+p.name)


def prepare(revision):
    info,model,layout=evidence()
    not_issued(layout)
    result,bank=fixture(layout,model)
    sources=[Path(__file__).resolve(),HERE/"derive_adjacent_writer.py",HERE/"adjacent_inputs.py",HERE.parent/"horizon_epoch162_split_scratch/second_interval.py"]
    published(revision,sources)
    save=layout["save"]
    proof=ROOT/"REDUCED_48_KERNEL_QUALIFICATION.json"
    if proof.exists():
        measured=layout["pinned"](proof)[0]
        a.need(measured["source_commit"]==revision and measured["profile"]==result and measured["refusal"]==REFUSAL
               and measured["prior_kernel_peak"]==PEAK,"different already qualified cap")
    else:
        save(proof,dict(source_commit=revision,profile=result,refusal=REFUSAL,prior_kernel_peak=PEAK,
                        cgroup=kernel_fixture(layout),terminal_fixture=bank),0o400)
    scope=dict(model,source_commit=revision,unissued_full_size_scope=info["scope"],original_interface=OLD_INTERFACE,
               quota=dict(model["quota"],producer_ram=LIMIT),reduced_memory_qualification=a.reference(proof))
    sr=save(SCOPE,scope,0o400)
    src=ROOT/"operator-48-source"
    src.mkdir(mode=0o700,exist_ok=True)
    a.need(src.resolve()==src and src.stat().st_uid==0 and not src.stat().st_mode & 0o077,"wrong reduced operator staging")
    members={}
    for name,body in files(sr["sha256"]).items():
        save(src/name,body)
        members[name]=(src/name,0o444)
    origin=src/"ORIGIN.json"
    save(origin,dict(revision=revision,scope=sr,original=info["provider"],refusal=REFUSAL,peak=PEAK,qualification=a.reference(proof),
                     source_sha256={p.name:a.digest(p) for p in sources}))
    members[origin.name]=origin,0o444
    a.shared.BASE=ROOT
    seal=a.shared.seal(members,PKG,save)
    return save(INTERFACE,dict(info,provider=seal,reader=a.reference(PKG/"status169.py"),scope=sr,
                               prior_interface=OLD_INTERFACE,refusal=REFUSAL,reduced_memory_qualification=a.reference(proof)),0o400)


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--prepare")
    args=cli.parse_args()
    if args.prepare:
        print(json.dumps(prepare(args.prepare),sort_keys=True))
    else:
        _,model,layout=evidence()
        print(json.dumps(fixture(layout,model)[0],sort_keys=True))
