"""Seal or issue only the compact epoch 169 operator against its complete current roster."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_adjacent_price as price
import compact_adjacent_writer as writer
import compact_adjacent_operator as c
import issue_adjacent as prior

a=c.a


def seal(layout,revision):
    a.need(prior.latest() in (price.OLD,price.NEW),"V33 was superseded")
    src=a.BASE/"shared-price-v34-source"
    src.mkdir(exist_ok=True,mode=0o700)
    a.need(src.resolve()==src and src.stat().st_uid==0 and not src.stat().st_mode & 0o077,"unsafe compact price staging")
    members={}
    for n,(body,mode) in price.build(revision).items():
        layout.save(src/n,body,mode)
        members[n]=src/n,mode
    a.shared.BASE=a.BASE
    deployed=a.shared.seal(members,price.NEW,layout.save)
    return layout.save(a.BASE/"SHARED_PRICE_V34.json",dict(package=deployed,revision=revision,
        prior=price.REF,interface=writer.INTERFACE,peak=c.PEAK,refusal=c.REFUSAL,qualification=writer.QUALIFICATION))


def spec(layout,revision):
    provider=layout.pinned(a.BASE/"SHARED_PRICE_V34.json")[0]
    a.need(prior.latest()==price.NEW and provider["revision"]==revision and provider["prior"]==price.REF
           and provider["interface"]==writer.INTERFACE and provider["qualification"]==writer.QUALIFICATION,"different compact price")
    package=layout.bound(provider["package"])
    refs=writer.bindings()
    model=layout.scope()
    directory=a.RT/"survivor172-cadence-20261122-v1"
    path=max(directory.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda p:int(p.name.split("_V")[1].split("_")[0]))
    active,ref=layout.pinned(path)
    ready=layout.bound(active["ready"])
    cap=price.NEW/"adjacent169_price.py"
    a.need(ready["adjacent169_interface"]==refs["INTERFACE"] and ready["adjacent169_provider"]==refs["OPERATOR"]
           and ready["adjacent169_scope"]==refs["SCOPE"] and ready["adjacent169_reader"]["sha256"]==refs["READER"]["sha256"]
           and ready["adjacent169_predecessor"]==refs["PREVIOUS"]==model["previous"]
           and package["destination"]==str(price.NEW) and any(m["name"]==cap.name and m["sha256"]==layout.digest(cap) for m in package["members"]),
           "active cadence has not registered the compact producer")
    return dict(schema="horizon-private-169-adjacent-enrollment-v1",writer_active=ref,operator=refs["OPERATOR"],
                interface=refs["INTERFACE"],previous=refs["PREVIOUS"],donor=dict(path=str(layout.DONOR),sha256=layout.DONOR_SHA),
                whole_roster=provider["package"],capacity=a.reference(cap),source_commit=revision,
                bootstrap=model["bootstrap"]["verified_local_custody"],guard_validation=model["native_guard_validation"],
                previous_refusal=c.REFUSAL,reduced_memory_qualification=writer.QUALIFICATION)


def issue(mode,revision):
    a.need(re.fullmatch("[0-9a-f]{40}",revision) and os.geteuid()==0 and __debug__,"published revision and root issuer required")
    prior.published(revision)
    c.published(revision,[HERE/f for f in ("compact_adjacent_operator.py","compact_adjacent_writer.py",
        "compact_adjacent_price.py","compact_adjacent_issue.py","compact_adjacent_progress.py")])
    op=runpy.run_path(str(c.PKG/"launch.py"))
    layout=op["l"]
    refs=writer.bindings()
    a.need(layout.PKG==c.PKG and layout.pinned(layout.HANDOFF)[1]==refs["SCOPE"] and layout.profile(44)["producer_memory_max"]==c.LIMIT,
           "different 169 compact issuer")
    with op["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode=="seal":
            return seal(layout,revision)
        model=spec(layout,revision)
        if layout.DATA.exists():
            enrolled,ref=layout.pinned(op["ENROLL"])
            held,hr=layout.pinned(layout.DATA/"HELD_OWNER.json")
            grant,gr=layout.pinned(layout.DATA/"GRANT.json")
            a.need(enrolled==model and grant["iid"]==held["producer_invocation_id"] and grant["held"]==hr
                   and grant["writer"]==ref and layout.bound(grant["postguard"])["fits"],"different 169 held scope or grant")
            return dict(recovered_grant=gr,invocation=grant["iid"])
        preview=layout.save(a.BASE/("ADJACENT_48_PREVIEW_"+str(time.time_ns())+".json"),dict(model,preview=True),0o400)
        q=runpy.run_path(model["capacity"]["path"])["quote"]("prestart",None,layout.profile(44),preview)
        ref=layout.save(a.BASE/("ADJACENT_48_PRESTART_PRICE_"+str(time.time_ns())+".json"),q,0o400)
        result=dict(fits=q["fits"],price=ref,home_margin=q["home_margin"],ram_margin=q["ram_margin"],guard_floor=q["guard_floor"],
                    fleet=q["fleet"],writer=q["writer"],cap=q["whole_roster"]["base_169"]["native"]["adjacent_169_effective_cap"])
        if mode=="launch" and q["fits"]:
            op["validate_quote"](q,"prestart",None,preview)
            result["enrollment"]=layout.save(op["ENROLL"],model,0o400)
            result["launch"]=op["launch"]()
        return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("seal","quote","launch"))
    p.add_argument("revision")
    arg=p.parse_args()
    print(json.dumps(issue(arg.mode,arg.revision),sort_keys=True),flush=True)
