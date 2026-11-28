"""Issue and qualify the single epoch 167 donor return after the V40 complete roster."""

import argparse
import ast
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from derive_v38 import PRICES, f, read_package
from derive_v39 import change
from qualify_v39 import isolate, refuses, LOCK, PUBLICATION
import released167_ram as ledger

OLD, NEW = PRICES / "issued-price-v40", PRICES / "issued-price-v41"
PRIOR = "4ffdbb56b8c7bb0ff2a7662987b2fc423327797545678bd9cb3c7e6659eb8d34"
STATE = ledger.ASSEMBLY
FIXTURE = STATE / "V41_RETURNED_167_RAM_FIXTURE.json"
PLAN = STATE / "V41_RETURNED_167_RAM_PLAN.json"


def members(stage, revision):
    prior = f.reference(OLD / "deployment-seal-receipt.json")
    f.need(prior["sha256"] == PRIOR, "different V40 predecessor")
    files = read_package(OLD,PRIOR)
    for name,(body,mode) in list(files.items()):
        if name.endswith(".py"):
            files[name] = body.replace(bytes(OLD),bytes(NEW)),mode
    code = files["capacity.py"][0].decode()
    start = "    peer, layout, proof, donor, base, row, fleet, own = common(None,read_only=True,prep143=prep143)"
    core = "    core = runpy.run_path(str(STOPPED.parent/'continuation_price.py'))['prior']"
    code = change(code,start,start+"\n"+core+'''
    handback = runpy.run_path(str(STOPPED.parent / "released167_ram.py"))
    handback["ratify_base"](base,core)''')
    code = change(code,core+"\n    core.prepare143_only = prep143","    core.prepare143_only = prep143")
    code = change(code,"    return nxt['final_runway'](json.loads(proc.stdout))",
                  "    return handback['reconcile'](nxt['final_runway'](json.loads(proc.stdout)),core)")
    code = change(code, "'closed143_original.py'}","'closed143_original.py','released167_ram.py'}")
    files["capacity.py"] = code.encode(),0o444
    files["released167_ram.py"] = (HERE/"released167_ram.py").read_bytes(),0o444
    info = json.loads(files["SOURCE.json"][0])
    info.update(revision=revision,prior_shared_price=prior,returned_unassigned_167_ram=ledger.RETURN,
                baseline_167_ram=f.reference(ledger.BASELINE),physical_ram_credit=0)
    files["SOURCE.json"] = (json.dumps(info,indent=2)+"\n").encode(),0o444
    result = {}
    for name,(blob,mode) in files.items():
        if name.endswith(".py"):
            ast.parse(blob.decode(),filename=name)
        path=stage/name
        path.write_bytes(blob)
        result[name]=path,mode
    return result


def suite(core, quoted):
    original = core.read(ledger.BASELINE,ledger.BASELINE_SHA)[0]["whole_roster"]
    base = copy.deepcopy(original["base_169"])
    ledger.ratify_base(base,core)
    credit = ledger.RETURN
    f.need(base["ram_margin"] == original["base_169"]["ram_margin"]+credit and base["fits"],"failed donor-margin counterfactual")
    zero_disk = copy.deepcopy(original["base_169"])
    zero_disk.update(home_margin=-1,fits=False)
    ledger.ratify_base(zero_disk,core)
    f.need(not zero_disk["fits"],"handback bypassed a disk refusal")
    q = copy.deepcopy(original)
    q["base_169"]=base
    truth = ledger.reconcile(q,core)
    f.need(truth["closed_167_suballocations"]["unassigned"]["ram_bytes"] == 0 and truth[ledger.FIELD]["newly_freed_physical_ram"] == 0,
           "unassigned donor changed")
    rejected = [refuses(lambda:ledger.ratify_base(base,core),"repeated base return"),
                refuses(lambda:ledger.reconcile(q,core),"repeated donor deduction")]
    for item in ("unassigned","guard","named","publication","157"):
        tampered=copy.deepcopy(original)
        tampered["base_169"]=base
        shares=tampered["closed_167_suballocations"]
        if item=="unassigned":
            shares["unassigned"]["ram_bytes"]-=1
        elif item=="guard":
            shares["guard_ram_separate"]-=1
        elif item=="named":
            shares["checksum_read"]["ram_bytes"]+=1
        elif item=="publication":
            tampered["publication168_allocation"]["memory_max"]-=1
        else:
            tampered["epoch157_lanej_rotation"]["sublease"]["ram_bytes"]+=1
        rejected.append(refuses(lambda:ledger.reconcile(tampered,core),item+" already claimed"))
    f.need(quoted["publication168_allocation"]["memory_max"] == 8<<30
           and quoted["original_172_accounting"]["retained_home_cap"] == 288<<30 and quoted["next_169_accounting"]
           and quoted["next_hourly170_accounting"] and quoted["fourth_162_accounting"],"other bookings lost")
    return dict(guarded_assembly=True,source_qualifier_classifier_checksum_preserved=True,
                publication_protected=True,negative_disk_preserved=True,refusals=rejected,
                original_ram_margin=original["ram_margin"],corrected_baseline_margin=base["ram_margin"])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("phase",choices=("plan","fixture","issue"))
    parser.add_argument("stage",type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    repo=HERE.parents[2]
    revision=f.git(repo,"rev-parse","HEAD").decode().strip()
    f.git(repo,"merge-base","--is-ancestor",revision,"refs/remotes/origin/account-updates")
    for filename in ("derive_v41.py","released167_ram.py"):
        path=HERE/filename
        f.need(path.read_bytes()==f.git(repo,"show",revision+":"+str(path.relative_to(repo))),"unmerged return code")
    latest=max((int(p.name.removeprefix("issued-price-v")),p) for p in PRICES.glob("issued-price-v[0-9]*")
               if p.name.removeprefix("issued-price-v").isdigit() and (p/"deployment-seal-receipt.json").is_file())[1]
    f.need(latest==OLD and not os.path.lexists(NEW),"shared provider already advanced")
    if args.phase=="plan":
        stage=Path(tempfile.mkdtemp(dir=args.stage,prefix="167-v41-members-"))
        items=members(stage,revision)
        plan=dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),
                  members=[dict(name=name,source=str(path),mode=mode,sha256=f.reference(path)["sha256"])
                           for name,(path,mode) in items.items()])
        print(json.dumps(dict(plan=f.save(PLAN,plan),revision=revision)));return
    pref=f.reference(PLAN)
    plan=f.read(pref)
    provenance=next(row for row in plan["members"] if row["name"]=="SOURCE.json")
    source=f.read(dict(path=provenance["source"],sha256=provenance["sha256"]))
    f.need(source["revision"]==revision and source["prior_shared_price"]["sha256"]==PRIOR
           and plan["destination"]==str(NEW),"different handback plan")
    if args.phase=="fixture":
        stage=Path(tempfile.mkdtemp(dir=args.stage,prefix="167-v41-ns-"))
        isolate(stage)
    else:
        proof=f.read(f.reference(FIXTURE))
        f.need(proof["plan"]==pref and proof["revision"]==revision and len(proof["checks"]["refusals"])==7
               and proof["checks"]["negative_disk_preserved"],"missing donor fixture")
    with LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        f.need(not NEW.exists() and f.reference(OLD/"deployment-seal-receipt.json")["sha256"]==PRIOR,
               "competing provider under lock")
        f.need(f.reference(f.SEALER)["sha256"]==f.SEALER_SHA,"different membership sealer")
        raw=subprocess.check_output([str(f.SEALER),str(PLAN),"--plan-sha256",pref["sha256"],"--self-sha256",f.SEALER_SHA])
        f.need(json.loads(raw)["outcome"]=="created","V41 provider already exists")
    seal=f.reference(NEW/"deployment-seal-receipt.json")
    q=json.loads(subprocess.check_output([str(PUBLICATION),"quote",seal["path"],seal["sha256"]]))
    whole=q["whole_roster"]
    f.need(whole["package"]==seal and whole[ledger.FIELD]["returned_bytes"]==ledger.RETURN and
           whole["guard_floor"]>0 and whole["closed_167_suballocations"]["remaining_producer_ram"]==42*(1<<30)-ledger.RETURN,
           "live release absent")
    checks=None
    if args.phase=="fixture":
        core=runpy.run_path(str(NEW/"continuation_price.py"))["prior"]
        checks=suite(core,whole)
    report=dict(plan=pref,revision=revision,seal=seal,checks=checks,quote=q)
    dest=FIXTURE if args.phase=="fixture" else STATE/"V41_RETURNED_167_RAM_LIVE_QUOTE.json"
    res=f.save(dest,report)
    print(json.dumps(dict(receipt=res,plan=pref,seal=seal,home_margin=q["home_margin"],ram_margin=q["ram_margin"],
                          fits=q["fits"],returned_bytes=ledger.RETURN,revision=revision)))


if __name__=="__main__":
    main()
