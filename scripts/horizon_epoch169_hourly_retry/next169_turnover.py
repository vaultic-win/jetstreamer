"""Seal the successor price or quote and issue the enrolled 169 worker on the sole fleet lock."""
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
import derive_next169_price as price
import next169_operator as op
import issue_adjacent as earlier

need = op.need
CADENCE = op.prior.RT/"survivor172-cadence-20261122-v1"


def inherited(directory, record):
    pkg = op.bind(record)
    need(pkg["destination"] == str(directory), "different price directory")
    files = {}
    for m in pkg["members"]:
        name = m["name"]
        path = directory/name
        s = path.lstat()
        need(path.parent == directory and path.resolve(strict=True) == path and name not in files
             and m["mode"] == "0444" and s.st_uid == 0 and not s.st_mode & 0o222 and s.st_nlink == 1
             and s.st_size == m["bytes"] and op.digest(path) == m["sha256"],"changed shared price member "+name)
        files[name] = path.read_bytes(),0o444
    return files


def issue_price(revision, layout):
    need(earlier.latest() in (price.OLD,price.NEW),"shared price was superseded")
    predecessor = op.reference(price.OLD/"deployment-seal-receipt.json")
    files = inherited(price.OLD,predecessor)
    files = price.extend(files,price.OLD,revision,predecessor)
    stage = op.BASE/"shared-price-v40-source"
    stage.mkdir(mode=0o700,exist_ok=True)
    need(stage.resolve(strict=True) == stage and stage.stat().st_uid == 0 and not stage.stat().st_mode & 0o077,
         "unsafe V40 staging directory")
    members = {}
    for name,(body,mode) in files.items():
        path = price.OLD/name
        if not path.is_file() or path.read_bytes() != body:
            path = stage/name
            layout.save(path,body,mode)
        members[name] = path,mode
    package = op.prior.shared.seal(members,price.NEW,layout.save,stage)
    return layout.save(op.BASE/"SHARED_PRICE_V40.json",dict(package=package,source_commit=revision,
        predecessor=predecessor,interface=price.INTERFACE,private_predecessor=op.HISTORY,donor=op.LEASE,
        fourth162_original_unissued_price=price.REFUSAL),0o400)


def enrollment(layout, revision):
    issued = layout.pinned(op.BASE/"SHARED_PRICE_V40.json")[0]
    directory = earlier.latest()
    need(issued["predecessor"] == op.reference(price.OLD/"deployment-seal-receipt.json") and issued["donor"] == op.LEASE
         and issued["interface"] == price.INTERFACE and issued["private_predecessor"] == op.HISTORY
         and not op.bind(price.REFUSAL)["fits"],"superseded or foreign 169 price")
    version = int(directory.name.removeprefix("issued-price-v"))
    current = op.reference(directory/"deployment-seal-receipt.json")
    link = current
    lineage = []
    need(version >= 40 and directory.parent == price.ROOT,"earlier or foreign admission provider")
    for index in range(version,40,-1):
        package_dir = price.ROOT/f"issued-price-v{index}"
        previous = layout.bound(link)
        source, raw = layout.pinned(package_dir/"SOURCE.json")
        need(link["path"] == str(package_dir/"deployment-seal-receipt.json") and previous["destination"] == str(package_dir)
             and any(m["name"]=="SOURCE.json" and m["sha256"]==raw["sha256"] for m in previous["members"])
             and source["next169_interface"] == price.INTERFACE and source["next169_predecessor"] == op.HISTORY
             and source["next169_donor"] == op.LEASE and source["fourth162_original_unissued_price"] == price.REFUSAL
             and all(any(m["name"]==n and m["sha256"]==layout.digest(price.NEW/n) for m in previous["members"])
                     for n in ("next169_peer.py","next169_price.py")),"successor changed the registered 169 reader or source")
        lineage.append(link)
        link = source["prior_shared_price"]
    need(link == issued["package"] and link == op.reference(price.NEW/"deployment-seal-receipt.json"),
         "new provider did not inherit the issued V40")
    info = layout.bound(price.INTERFACE)
    scope = layout.scope()
    active = max(CADENCE.glob("FAILED166_CADENCE_V*_ACTIVE.json"), key=lambda p:int(p.name.split("_V")[1].split("_")[0]))
    writer, ref = layout.pinned(active)
    ready = layout.bound(writer["ready"])
    cap = directory/"next169_price.py"
    pkg = layout.bound(current)
    need(info["scope"] == ready["next169_scope"] and info["provider"] == ready["next169_provider"]
         and ready["next169_reader"]["sha256"] == info["reader"]["sha256"]
         and ready["next169_interface"] == price.INTERFACE and ready["next169_predecessor"] == op.HISTORY
         and ready["next169_donor"] == op.LEASE and ready["adjacent169_interface"] == op.INTERFACE
         and ready["fourth162_interface"]["sha256"] == "d0aeddbde2ebef0a6a015dfd06e8917c0842cd7701f1b559fdb3887acd88d396"
         and ready["next_hourly170_interface"] and scope["previous"] == info["previous"] == op.HISTORY
         and pkg["destination"] == str(directory) and any(m["name"] == cap.name and m["sha256"] == layout.digest(cap)
                                                          for m in pkg["members"]),"different writer, shared price or predecessor")
    return dict(schema="horizon-private-169-next-enrollment-v1",writer_active=ref,operator=info["provider"],
                donor=op.LEASE,capacity=op.reference(cap),whole_roster=current,source_commit=revision,
                price_lineage=lineage+[link],
                interface=price.INTERFACE,previous=op.HISTORY,guard_validation=info["guard_validation"],
                bootstrap=op.CUSTODY,reduced_memory_qualification=info["reduced_memory_qualification"])


def run(mode, revision):
    files = ["next169_operator.py","derive_next169_price.py","next169_account.py","next169_turnover.py"]
    op.published(revision,[HERE/n for n in files])
    launch = runpy.run_path(str(op.PKG/"launch.py"))
    layout = launch["l"]
    need(os.geteuid()==0 and __debug__ and layout.PKG == op.PKG and layout.DONOR_SHA == op.LEASE["sha256"],
         "incorrect operator or booking")
    with launch["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode == "seal":
            return issue_price(revision, layout)
        spec = enrollment(layout,revision)
        if layout.DATA.exists():
            existing, ref = layout.pinned(launch["ENROLL"])
            held, hr = layout.pinned(layout.DATA/"HELD_OWNER.json")
            grant, gr = layout.pinned(layout.DATA/"GRANT.json")
            need(existing == spec and grant["iid"] == held["producer_invocation_id"] and grant["held"] == hr
                 and grant["writer"] == ref and layout.bound(grant["postguard"])["fits"],"different existing 169 grant")
            return dict(grant=gr,invocation=grant["iid"])
        request = layout.save(op.BASE/f"NEXT169_PREVIEW_{time.time_ns()}.json",dict(spec,preview=True),0o400)
        q = runpy.run_path(spec["capacity"]["path"])["quote"]("prestart",None,layout.profile(44),request)
        accepted = layout.save(op.BASE/f"NEXT169_PRICE_{time.time_ns()}.json",q,0o400)
        result = dict(price=accepted,fits=q["fits"],home_margin=q["home_margin"],ram_margin=q["ram_margin"],guard_floor=q["guard_floor"])
        if q["fits"] and mode == "launch":
            launch["validate_quote"](q,"prestart",None,request)
            result["enrollment"] = layout.save(launch["ENROLL"],spec,0o400)
            result["launch"] = launch["launch"]()
        return result


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode",choices=("seal","quote","launch"))
    cli.add_argument("revision")
    args = cli.parse_args()
    print(json.dumps(run(args.mode,args.revision),sort_keys=True),flush=True)
