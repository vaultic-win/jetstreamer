"""Seal the shared V33 price and issue the single registered epoch 169 interval."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import derive_adjacent_price as derivation
import adjacent_inputs as a
from adjacent_price import latest
from derive_adjacent_writer import INTERFACE

SOURCES=("adjacent_inputs.py","adjacent_operator.py","adjacent_account.py","adjacent_price.py","derive_adjacent_price.py",
         "adjacent_writer.py","derive_adjacent_writer.py","issue_adjacent.py","adjacent_progress.py")


def published(revision):
    checkout=HERE.parents[1]
    git=["git","-c","safe.directory="+str(checkout),"-C",str(checkout)]
    a.need(re.fullmatch("[0-9a-f]{40}",revision),"a full source revision is required")
    subprocess.run([*git,"merge-base","--is-ancestor",revision,"origin/account-updates"],check=True)
    paths=[HERE/n for n in SOURCES]
    paths += [HERE.parent/"horizon_epoch162_split_scratch"/name for name in ("second_interval.py","third162_first_progress.py")]
    for p in paths:
        rel=str(p.relative_to(checkout))
        a.need(subprocess.check_output([*git,"show",revision+":"+rel])==p.read_bytes(),"unpublished "+rel)


def seal(layout,revision):
    a.need(latest() in (derivation.OLD,derivation.NEW),"V32 has been superseded by another owner")
    rows=derivation.build(revision)
    stage=a.BASE/"shared-price-v33-source"
    stage.mkdir(exist_ok=True,mode=0o700)
    a.need(stage.resolve()==stage and stage.stat().st_uid==0 and not stage.stat().st_mode & 0o077,"unsafe price staging")
    inputs={}
    for name,(data,mode) in rows.items():
        path=stage/name
        layout.save(path,data,mode)
        inputs[name]=path,mode
    a.shared.BASE=a.BASE
    sealref=a.shared.seal(inputs,derivation.NEW,layout.save)
    out=layout.save(a.BASE/"SHARED_PRICE_V33.json",dict(package=sealref,interface=INTERFACE,revision=revision,prior=derivation.REF))
    return dict(package=sealref,receipt=out)


def spec(layout,revision):
    deployed=layout.pinned(a.BASE/"SHARED_PRICE_V33.json")[0]
    current=latest()
    a.need(deployed["revision"]==revision and deployed["prior"]==derivation.REF and deployed["interface"]==INTERFACE
           and current==derivation.NEW,"unexpected 169 price issuer or successor")
    pkg=layout.bound(deployed["package"])
    model=layout.scope()
    interface=layout.bound(INTERFACE)
    writer_dir=a.RT/"survivor172-cadence-20261122-v1"
    active_path=max(writer_dir.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda p:int(p.name.split("_V")[1].split("_")[0]))
    active,writer=layout.pinned(active_path)
    ready=layout.bound(active["ready"])
    path=current/"adjacent169_price.py"
    a.need(pkg["destination"]==str(current) and
           any(m["name"]==path.name and m["sha256"]==layout.digest(path) for m in pkg["members"])
           and ready["adjacent169_interface"]==INTERFACE and ready["adjacent169_provider"]==interface["provider"]
           and ready["adjacent169_reader"]["sha256"]==interface["reader"]["sha256"]
           and ready["adjacent169_scope"]==interface["scope"]
           and ready["adjacent169_predecessor"]==interface["previous"]==model["previous"],"writer has not registered this 169 scope")
    return dict(schema="horizon-private-169-adjacent-enrollment-v1",writer_active=writer,operator=interface["provider"],
                interface=INTERFACE,previous=model["previous"],donor=dict(path=str(layout.DONOR),sha256=layout.DONOR_SHA),
                whole_roster=deployed["package"],capacity=a.reference(path),source_commit=revision,
                bootstrap=model["bootstrap"]["verified_local_custody"],guard_validation=interface["guard_validation"])


def issue(mode,revision):
    published(revision)
    op=runpy.run_path(str(a.BASE/"operator-v1/launch.py"))
    layout=op["l"]
    a.need(os.geteuid()==0 and __debug__ and layout.BASE==a.BASE,"use the registered root issuer")
    if mode=="fixture":
        entries=derivation.build(revision)
        return dict(modules=len(entries),parent=derivation.REF,changed=[k for k,v in entries.items() if
            k not in ("SOURCE.json",) and (not (derivation.OLD/k).is_file() or v[0]!=(derivation.OLD/k).read_bytes())])
    with op["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode=="seal":
            return seal(layout,revision)
        model=spec(layout,revision)
        if layout.DATA.exists():
            existing,ref=layout.pinned(op["ENROLL"])
            held,hr=layout.pinned(layout.DATA/"HELD_OWNER.json")
            grant,gr=layout.pinned(layout.DATA/"GRANT.json")
            a.need(existing==model and grant["iid"]==held["producer_invocation_id"] and grant["held"]==hr
                   and grant["writer"]==ref and layout.bound(grant["postguard"])["fits"],"existing 169 release did not match")
            return dict(recovered_grant=gr,unit=layout.UNIT,invocation=grant["iid"])
        preview=layout.save(a.BASE/("ADJACENT_PREVIEW_"+str(time.time_ns())+".json"),dict(model,preview=True),0o400)
        result=runpy.run_path(model["capacity"]["path"])["quote"]("prestart",None,layout.profile(44),preview)
        receipt=layout.save(a.BASE/("ADJACENT_PRESTART_PRICE_"+str(time.time_ns())+".json"),result,0o400)
        out=dict(price=receipt,fits=result["fits"],home_margin=result["home_margin"],ram_margin=result["ram_margin"],
                 guard_floor=result["guard_floor"],writer=result["writer"])
        if mode=="launch" and result["fits"]:
            op["validate_quote"](result,"prestart",None,preview)
            out["enrolled"]=layout.save(op["ENROLL"],model,0o400)
            out["launch"]=op["launch"]()
        return out


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode",choices=("fixture","seal","quote","launch"))
    cli.add_argument("revision")
    arg=cli.parse_args()
    print(json.dumps(issue(arg.mode,arg.revision),sort_keys=True),flush=True)
