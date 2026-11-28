"""Seal the fourth price, quote or issue only its registered receiver while holding the original fleet lock."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import runpy
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import fourth162_price as p
from fourth162_writer import COMMON, ROOT as CADENCE, WRITERS, contract, published
from third162_price import latest_provider

BASE = p.BASE
OP = BASE/"operator-v1"


def confirm(revision):
    own = ("fourth162_price.py","issue_fourth162.py","fourth162_writer.py","fourth_interval.py","third162_price.py",
           "derive_third162_writer.py","transition_v74.py","third_inputs.py","third_interval.py","second_interval.py")
    published(revision,[*(HERE/n for n in own),WRITERS/"derive69.py",WRITERS/"derive63.py",WRITERS/"derive143_bootstrap_retry.py",
                        COMMON/"following_prepare.py",COMMON/"closed_successor.py"])


def seal(layout, revision):
    p.need(latest_provider() in (p.OLD,p.NEW), "different shared provider")
    interface,info = contract(p.INTERFACE_SHA)
    scope = layout.bound(info["scope"])
    p.need(scope["previous"]["sha256"] == p.PRIOR_SHA and scope["native_guard_validation"] == info["guard_validation"],"different fourth custody evidence")
    source = BASE/"shared-price-v35-source"
    source.mkdir(mode=0o700,exist_ok=True)
    p.need(source.resolve()==source and source.stat().st_uid==0 and not source.stat().st_mode & 0o077,"invalid V35 source directory")
    members = {}
    for name,(body,mode) in p.members(revision).items():
        layout.save(source/name,body,mode)
        members[name] = source/name,mode
    result = p.writer.seal(p.NEW,members,BASE/"SHARED_PRICE_V35_PLAN.json")
    return layout.save(BASE/"FOURTH_SHARED_PRICE_V35.json",dict(package=result,interface=interface,source_commit=revision,
                       predecessor=dict(path=str(p.OLD/"deployment-seal-receipt.json"),sha256=p.PIN)),0o400)


def spec(layout,revision):
    root,_ = layout.pinned(BASE/"FOURTH_SHARED_PRICE_V35.json")
    interface,info = contract(p.INTERFACE_SHA)
    source = layout.bound(root["package"])
    need = layout.need
    need(root["source_commit"]==revision and root["interface"]==interface and latest_provider()==p.NEW
         and source["destination"]==str(p.NEW) and root["predecessor"]==dict(path=str(p.OLD/"deployment-seal-receipt.json"),sha256=p.PIN),
         "different fourth provider or registration")
    active_path = max(CADENCE.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda path:int(path.name.split("_V")[1].split("_")[0]))
    active,writer = layout.pinned(active_path)
    ready = layout.bound(active["ready"])
    need(ready["fourth162_scope"]==info["scope"] and ready["fourth162_interface"]==interface
         and ready["fourth162_provider"]==info["provider"] and ready["fourth162_reader"]["sha256"]==info["reader"]["sha256"]
         and ready["fourth162_predecessor"]==info["previous"] and ready["third162_interface"]["sha256"]==p.writer.run.OLD_INTERFACE_SHA
         and ready["adjacent169_interface"] and ready["epoch167_assembly_owner"],"writer did not enroll the full roster")
    price = p.NEW/"fourth162_price.py"
    cap = dict(path=str(price),sha256=layout.digest(price))
    need(any(v["name"]==price.name and v["sha256"]==cap["sha256"] for v in source["members"]),"unsealed fourth price")
    return dict(schema="horizon-private-162-fourth-enrollment-v1",writer_active=writer,operator=info["provider"],
                donor=dict(path=str(layout.DONOR),sha256=layout.DONOR_SHA),capacity=cap,whole_roster=root["package"],
                third_terminal=info["previous"],interface=interface,guard_validation=info["guard_validation"],
                bootstrap=info["bootstrap"]["verified_local_custody"],source_commit=revision)


def issue(mode,revision):
    confirm(revision)
    launch = runpy.run_path(str(OP/"launch.py"))
    layout = launch["l"]
    layout.need(os.geteuid()==0 and __debug__ and layout.BASE==BASE,"use the sealed private operator")
    with launch["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode == "seal":
            return dict(shared_price=seal(layout,revision))
        entry = spec(layout,revision)
        if layout.DATA.exists():
            old,ref = layout.pinned(launch["ENROLL"])
            actor,held = layout.pinned(layout.DATA/"HELD_OWNER.json")
            permit,grant = layout.pinned(layout.DATA/"GRANT.json")
            layout.need(old==entry and permit["held"]==held and permit["iid"]==actor["producer_invocation_id"]
                        and permit["writer"]==ref and layout.bound(permit["postguard"])["fits"],"existing fourth grant belongs to another owner")
            return dict(grant=grant,invocation=permit["iid"])
        packet = layout.save(BASE/("FOURTH_PREVIEW_"+str(time.time_ns())+".json"),dict(entry,preview=True),0o400)
        price = runpy.run_path(entry["capacity"]["path"])["quote"]("prestart",None,layout.profile(36),packet)
        observed = layout.save(BASE/("FOURTH_NATIVE_PRICE_"+str(time.time_ns())+".json"),price,0o400)
        answer = dict(price=observed,fits=price["fits"],home_margin=price["home_margin"],ram_margin=price["ram_margin"],
                      guard_floor=price["guard_floor"],writer=price["writer"])
        if mode == "launch" and price["fits"]:
            launch["validate_quote"](price,"prestart",None,packet)
            answer["enrolled"] = layout.save(launch["ENROLL"],entry,0o400)
            answer["issued"] = launch["launch"]()
        return answer


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=["seal","quote","launch"])
    parser.add_argument("revision")
    args=parser.parse_args()
    print(json.dumps(issue(args.mode,args.revision),sort_keys=True),flush=True)
