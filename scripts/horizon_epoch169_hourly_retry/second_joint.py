"""Admit the second 169 attempt from the shared 169/170 price and guarded writer."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import time


RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT=RT/"epoch169-hourly-retry-20261128-v2"
DIR=ROOT/"issuer-v1"
OP=ROOT/"operator-v1"
PRICE=RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v9"
OP_SHA="904ceb6b6d3f97f5e3c2dce585cff64254c05aee6fdc4d5f229fa92c62d7a876"
PRICE_SHA="d97547403106754db04ef006b72e5e4f60f6d92a90723a3fc312f7bb56bb0066"
SCOPE="322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e"
CLOSURE="24d2fc5ecf736827e0b06af6194f85ad1dae055f33065d6e9e20606eb17ee9dc"
PEER="horizon-qualify-170-from-73760367-ram-20261128-v1.service"
G=1<<30


def load():
    seal=OP/"deployment-seal-receipt.json"
    raw=seal.read_bytes()
    if not stat.S_ISREG(seal.lstat().st_mode) or seal.resolve()!=seal or seal.lstat().st_uid!=0 or seal.lstat().st_mode&0o222 or hashlib.sha256(raw).hexdigest()!=OP_SHA:
        raise ValueError("different second 169 operator")
    for row in json.loads(raw)["members"]:
        path=OP/row["name"]
        s=path.lstat()
        if (path.parent!=OP or path.resolve()!=path or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1
            or s.st_mode&0o222 or s.st_size!=row["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest()!=row["sha256"]):
            raise ValueError("changed second 169 operator member "+row["name"])
    return runpy.run_path(str(OP/"issuer.py"))


def geometry(whole, other, output):
    available=whole["available_home"]
    if output<=0 or available-whole["required_home"]<whole["home_margin"] or whole["available_ram"]-whole["required_ram"]!=whole["ram_margin"]:
        raise ValueError("inconsistent common budget")
    floor=max(whole["guard_floor"],whole["required_home"]-output,available-whole["home_margin"]-output,other)
    return floor, available-floor-output


def price(owner, scope, sr, preliminary=False):
    c,q=owner["c"],owner["quote"]
    rr=q.verified_provider(PRICE,PRICE_SHA)
    binding,br=c.read(DIR/"SOURCE.json")
    c.need(binding["provider"]==rr and binding["scope"]==sr and binding["source"]["remote_contains_commit"]
           and scope["operator"]==dict(path=str(OP/"deployment-seal-receipt.json"),sha256=OP_SHA)
           and sr==dict(path=str(ROOT/"SCOPE.json"),sha256=SCOPE) and scope["first_gate_closure"]["sha256"]==CLOSURE,
           "different 169 admission or provider binding")
    derivation,_=c.read(PRICE/"SOURCE.json","8a98615ca486ed481ad897acb360b8423d3ce51dc4da8d7034327654f22b0c3f")
    c.need(derivation["second_169_scope"]==SCOPE and not derivation["replay_authorized"],"different bilateral source")
    partial=q.bound(scope["predecessor"])["retained_incomplete_archive"]
    retained=Path(partial["path"])
    identity=c.identity(retained.lstat())
    c.need(all(partial[k]==v for k,v in identity.items()),"changed original 169 archive custody")
    loan=q.returned_loan()
    whole=runpy.run_path(str(PRICE/"capacity.py"))["whole_roster"]()
    base=whole["base_169"]
    native=base["native"]
    paid=native["planned_169_retry"]
    gap=native["ram_retry_cost"]
    other=native["ram_gap170"]
    actor=native["independent_retry169"]
    same_epoch=[r for r in base["observed_actors"] if r["epoch"]==169]
    other_epoch=[r for r in base["observed_actors"] if r["epoch"]==170]
    def roster(row, epoch, unit):
        return ([] if not row else [dict(epoch=epoch,unit=unit,invocation_id=row["invocation"])])
    c.need(whole["package"]==rr and paid["second_scope"]==sr and paid["first_unreleased_closure"]==scope["first_gate_closure"]
           and paid["additional_ram"]==gap["extra_ram"]==8*G and paid["additional_home"]==c.HOME_OUTPUT+c.CONTROL_BYTES
           and paid["original_169_guard_retained"] and paid["original_170_guard_cpu_retained"]
           and native["stopped_169_compute_handoff"]["retained_169_output_bytes"]==8*G
           and native["stopped_169_compute_handoff"]["retained_159_ram"]+paid["additional_ram"]==c.RAM
           and native["independent_gap_funding"]["cpu_donor"]==loan["scope"] and gap["producer_memory_max"]==56*G
           and gap["scratch_tmpfs"]==40*G and gap["home_growth"]==8*G and gap["original_guard_still_budgeted"]
           and not whole["resource_credit_bytes"] and same_epoch==roster(actor,169,c.UNIT)
           and other_epoch==roster(other,170,PEER) and (not other or other["unit"]==PEER and other["phase"] in ("held","bootstrap","worker"))
           and q.returned_loan()==loan and c.identity(retained.lstat())==identity,"joint reservation or surviving actor changed")
    writer=whole["writer"]
    if not preliminary:
        active=owner["read_active_writer"](c,writer)
        ready=q.bound(active["ready"])
        c.need(ready.get("private169_retry2_scope")==sr and ready.get("private169_retry2_cadence")==scope["cadence_source"]
               and not active["producer_mutations"],"active writer has not enrolled second 169")
    other_floor=(other["floor"] or 0) if other else 0
    floor,margin=geometry(whole,other_floor,c.HOME_OUTPUT)
    return dict(schema="horizon-169-second-attempt-native-price-v1",recorded_unix=time.time(),scope=sr,provider=rr,
                registration=br,writer=writer,first_closure=scope["first_gate_closure"],predecessor_custody=scope["predecessor"],
                returned_159_loan=loan,whole_roster=whole,stage="native-postguard" if actor else "native-prestart",
                guard_floor=floor,home_margin=margin,ram_margin=whole["ram_margin"],other_armed_floor=other_floor,
                fits=bool(whole["fits"] and margin>=0 and whole["ram_margin"]>=0),preliminary=preliminary,resource_credit_bytes=0,
                canonical_publication_authorized=False)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("prepare-quote","quote","launch","first-progress"))
    args=cli.parse_args()
    owner=load()
    c=owner["c"]
    c.need(Path(__file__).resolve()==DIR/"second_joint.py","use the sealed second-attempt issuer")
    scope,sr=c.read(ROOT/"SCOPE.json",SCOPE)
    if args.action=="first-progress":
        result=runpy.run_path(str(DIR/"first_progress.py"))["follow"](owner,scope,sr)
    else:
        with owner["quote"].LOCK.open("rb") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if args.action=="launch":
                start=owner["launch"]
                start.__globals__["funded"]=lambda s,r:price(owner,s,r)
                result=start()
            else:
                value=price(owner,scope,sr,preliminary=args.action=="prepare-quote")
                result=c.recorded(ROOT/f"JOINT_{time.time_ns()}.json",value)
    print(json.dumps(result))
