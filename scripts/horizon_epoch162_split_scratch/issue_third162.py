"""Seal the shared price or issue the third bounded replay with the enrolled writer under the fleet lock."""
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

sys.path.insert(0,str(Path(__file__).resolve().parent))
import derive_third162_price_v29 as common
from third162_price import latest_provider

BASE = common.BASE
OP = BASE/"operator-v1"
INTERFACE = dict(path=str(BASE/"INTERFACE.json"),sha256="0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3")


def published(revision):
    checkout = common.HERE.parents[1]
    git = ["git","-c","safe.directory="+str(checkout),"-C",str(checkout)]
    common.f.need(re.fullmatch("[a-f0-9]{40}",revision), "expected a full source commit")
    subprocess.run([*git,"merge-base","--is-ancestor",revision,"origin/account-updates"],check=True)
    paths = [common.HERE/n for n in ("derive_third162_price_v29.py","third162_account.py","third162_price.py","issue_third162.py",
                                      "third_inputs.py","second_interval.py","third162_route.py","derive_third162_writer.py")]
    t = common.HERE.parent/"horizon_epoch170_checkpoint_suffix"
    paths.extend([t/"following_prepare.py",t/"closed_successor.py",t/"derive_serial157_v23.py",t/"derive_ram170_writer.py",
                  common.HERE.parent/"horizon_epoch143_bounded_entry_20261126_v1/writer/derive143_bootstrap_retry.py"])
    for p in paths:
        relative = str(p.relative_to(checkout))
        common.f.need(subprocess.check_output([*git,"show",revision+":"+relative]) == p.read_bytes(), "unpublished source "+relative)


def seal(layout, prior, revision):
    published(revision)
    common.f.need(latest_provider() in (common.OLD,common.NEW), "V28 or V29 must own shared pricing")
    info = layout.bound(INTERFACE)
    scope = layout.bound(info["scope"])
    native = scope["source_commit"]
    published_files = ["third_interval.py","third_inputs.py","second_interval.py"]
    origin = layout.bound(dict(path=str(OP/"ORIGIN.json"),sha256=layout.digest(OP/"ORIGIN.json")))
    common.f.need(origin["revision"] == native and all(layout.digest(common.HERE/n) ==
                  origin["sources"]["scripts/horizon_epoch162_split_scratch/"+n] for n in published_files),
                  "different confirmed native operator or preparer")
    members = common.members(BASE/"shared-price-v29-source",revision,prior,INTERFACE)
    result = common.f.seal(common.NEW,members,BASE/"SHARED_PRICE_V29_PLAN.json")
    layout.save(BASE/"THIRD_SHARED_PRICE_V29.json",dict(package=result,interface=INTERFACE,source_commit=revision),0o400)
    return result


def verify_descendants(layout, current, pin, revision):
    root,_ = layout.pinned(BASE/"THIRD_SHARED_PRICE_V29.json")
    trusted = root["package"]
    layout.need(root["source_commit"] == revision and root["interface"] == INTERFACE and
                trusted["path"] == str(common.NEW/"deployment-seal-receipt.json"), "different registered 162 provider")
    basis = {m["name"]:m["sha256"] for m in layout.bound(trusted)["members"]}
    for version in range(30,int(current.name.removeprefix("issued-price-v"))+1):
        directory = common.NEW.with_name("issued-price-v"+str(version))
        seal,child = layout.pinned(directory/"deployment-seal-receipt.json")
        members = {m["name"]:m["sha256"] for m in seal["members"]}
        history,_ = layout.pinned(directory/"SOURCE.json",members["SOURCE.json"])
        layout.need(seal["destination"] == str(directory) and history["prior_shared_price"] == trusted
                    and history["third162_interface"] == INTERFACE and all(members.get(k) == basis[k]
                    for k in ("third162_peer.py","third162_price.py")), "incompatible successor common provider")
        trusted = child
    layout.need(trusted == dict(path=str(current/"deployment-seal-receipt.json"),sha256=pin), "different latest shared price")


def make_spec(layout, shared, revision):
    current = latest_provider()
    verify_descendants(layout,current,shared,revision)
    manifest, receipt = layout.pinned(current/"deployment-seal-receipt.json",shared)
    history,_ = layout.pinned(current/"SOURCE.json")
    if current == common.NEW:
        common.f.need(history["revision"] == revision and history["third162_interface"] == INTERFACE,
                      "different third interval price deployment")
    ready_dir = layout.RT/"survivor172-cadence-20261122-v1"
    active_path = max(ready_dir.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda p:int(p.name.split("_V",1)[1].split("_")[0]))
    active,writer = layout.pinned(active_path)
    ready = layout.bound(active["ready"])
    info = layout.bound(INTERFACE)
    scope = layout.bound(info["scope"])
    price = current/"third162_price.py"
    common.f.need(ready["third162_interface"] == INTERFACE and ready["third162_scope"] == info["scope"]
                  and ready["third162_provider"] == info["provider"] and ready["third162_reader"]["sha256"] == info["reader"]["sha256"]
                  and ready["third162_predecessor"] == info["previous"] == scope["previous"]
                  and scope["native_guard_validation"] == info["guard_validation"]
                  and manifest["destination"] == str(current) and any(m["name"] == price.name and m["sha256"] ==
                  layout.digest(price) for m in manifest["members"]), "different enrolled writer, third checkpoint or price")
    return dict(schema="horizon-private-162-third-enrollment-v1",writer_active=writer,operator=info["provider"],
                donor=dict(path=str(layout.DONOR),sha256=layout.DONOR_SHA),capacity=common.f.reference(price),
                whole_roster=receipt,second_terminal=scope["previous"],interface=INTERFACE,
                guard_validation=info["guard_validation"],bootstrap=scope["bootstrap"]["verified_local_custody"],
                source_commit=revision)


def issue(mode, pin, revision):
    launch = runpy.run_path(str(OP/"launch.py"))
    layout = launch["l"]
    layout.need(os.geteuid() == 0 and __debug__ and layout.BASE == BASE, "use the sealed private interval")
    with launch["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode == "seal":
            return dict(shared_price=seal(layout,pin,revision))
        published(revision)
        spec = make_spec(layout,pin,revision)
        if layout.DATA.exists():
            held, ref = layout.pinned(layout.DATA/"HELD_OWNER.json")
            grant, released = layout.pinned(layout.DATA/"GRANT.json")
            saved,record = layout.pinned(launch["ENROLL"])
            layout.need(saved == spec and grant["held"] == ref and grant["iid"] == held["producer_invocation_id"]
                        and grant["writer"] == record and layout.bound(grant["postguard"])["fits"],
                        "existing 162 transaction has different enrollment or ownership")
            return dict(recovered_grant=released, invocation_id=grant["iid"],unit=layout.UNIT)
        params = layout.save(BASE/("THIRD_PREVIEW_"+str(time.time_ns())+".json"),dict(spec,preview=True),0o400)
        q = runpy.run_path(spec["capacity"]["path"])["quote"]("prestart",None,layout.profile(36),params)
        observed = layout.save(BASE/("THIRD_NATIVE_PRICE_"+str(time.time_ns())+".json"),q,0o400)
        result = dict(price=observed,fits=q["fits"],home_margin=q["home_margin"],ram_margin=q["ram_margin"],
                      guard_floor=q["guard_floor"],writer=q["writer"])
        if mode == "quote" or not q["fits"]:
            return result
        launch["validate_quote"](q,"prestart",None,params)
        result["enrolled"] = layout.save(launch["ENROLL"],spec,0o400)
        result["issued"] = launch["launch"]()
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("seal","quote","launch"))
    parser.add_argument("price_pin",help="V28 seal digest for seal or the current registered shared seal digest for quote/launch")
    parser.add_argument("revision")
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{64}",args.price_pin):
        parser.error("expected a full shared price SHA-256")
    print(json.dumps(issue(args.mode,args.price_pin,args.revision),sort_keys=True),flush=True)
