"""Feed the common 169/170 price into the qualified 169 held issuer without double charging."""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import runpy
import stat
import time


RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT=RT/"epoch169-hourly-retry-20261128-v1"
OPERATOR=ROOT/"operator-v1"
PARENT=ROOT/"roster-v1"
PEER=RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v8-prestart"
DEPLOY=ROOT/"joint-issuer-v1"
BASE_SCOPE="eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a"
BASE_OPERATOR="8e87b305ba3957ca579a9eafa696eb2410f2498869c31922a8460dc5935943ed"
BASE_ROSTER="c07e0827f8bc7fe26e46f644b03e0012def68ad666a026df243a1238cd52c353"
HISTORIC_PREPARE="7bb806756c04a08ce1a476d01528b736c9b01ba6a3629b5f015a72634f8f6ef6"


def load_owner():
    seal=OPERATOR/"deployment-seal-receipt.json"
    st=seal.lstat()
    raw=seal.read_bytes()
    if (seal.resolve()!=seal or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o222
        or hashlib.sha256(raw).hexdigest()!=BASE_OPERATOR):
        raise ValueError("different 169 operator")
    for row in json.loads(raw)["members"]:
        path=OPERATOR/row["name"]
        s=path.lstat()
        if (path.parent!=OPERATOR or path.resolve()!=path or not stat.S_ISREG(s.st_mode)
            or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o222 or s.st_size!=row["bytes"]
            or hashlib.sha256(path.read_bytes()).hexdigest()!=row["sha256"]):
            raise ValueError("changed sealed 169 operator member")
    return runpy.run_path(str(OPERATOR/"issuer.py"))


def geometry(whole, output):
    if (whole["available_home"] - whole["required_home"] != whole["home_margin"]
        or whole["available_ram"] - whole["required_ram"] != whole["ram_margin"] or output <= 0):
        raise ValueError("inconsistent joint HOME or RAM screen")
    # The common total already pays for this tree and its control. Remove
    # only its output to compute the minimum free space required at runtime.
    floor=max(whole["guard_floor"],whole["required_home"]-output)
    home=whole["available_home"]-floor-output
    return floor, home, whole["ram_margin"]


def jointly_funded(owner, scope, ref, *, preliminary=False):
    c,quote=owner["c"],owner["quote"]
    binding,br=c.read(DEPLOY/"binding.json")
    c.need(ref=={"path":str(ROOT/"SCOPE.json"),"sha256":BASE_SCOPE}
           and binding["scope"]==ref and scope["operator"]["sha256"]==BASE_OPERATOR
           and scope["roster"]["sha256"]==BASE_ROSTER and binding["provider"]["path"]==str(PEER/"deployment-seal-receipt.json")
           and binding["source"]["commit"] and binding["source"]["branch"]=="origin/account-updates"
           and binding["source"]["remote_contains_commit"], "different common provider binding")
    prov=quote.verified_provider(PEER,binding["provider"]["sha256"])
    derivation,_=c.read(PEER/"SOURCE.json")
    c.need(derivation["peer169"]==scope["roster"] and derivation["predecessor"]["sha256"]==
           "8f9377d8b0405d60fb7687b4195b8c69b45451f864971358d902b4221df748ee", "common quote lost the two native 169 censuses")
    prior=quote.bound(scope["predecessor"])["retained_incomplete_archive"]
    partial=Path(prior["path"])
    identity=c.identity(partial.lstat())
    c.need(all(prior[k]==v for k,v in identity.items()), "private 169 predecessor changed")
    loan=quote.returned_loan()
    whole=runpy.run_path(str(PEER/"capacity.py"))["whole_roster"]()
    base=whole["base_169"]
    native=base["native"]
    new169=native["planned_169_retry"]
    new170=native["ram_retry_cost"]
    transfer=native["stopped_169_compute_handoff"]
    c.need(whole["package"]==prov and new169["prepare"]["sha256"]==HISTORIC_PREPARE
           and new169["additional_home"]==c.HOME_OUTPUT+c.CONTROL_BYTES and new169["additional_ram"]==8*c.G
           and new169["original_169_guard_retained"] and new169["original_170_guard_cpu_retained"]
           and new170["previous_stop"]["iid"]==quote.GAP_IID and new170["original_guard_still_budgeted"]
           and new170["original_home_growth"]==36*c.G and new170["home_growth"]==8*c.G
           and new170["producer_memory_max"]==60*c.G and new170["scratch_tmpfs"]==40*c.G and new170["extra_ram"]==12*c.G
           and transfer["retained_159_ram"]==48*c.G and transfer["retained_guard_ram"]==c.GUARD_RAM
           and transfer["retained_169_output_bytes"]==8*c.G and native["independent_gap_funding"]["cpu_donor"]==loan["scope"]
           and "independent_retry169" in native and native["ram_gap170"] is None
           and not any(row["epoch"]==170 for row in base["observed_actors"])
           and whole["available_home"]-whole["required_home"]==whole["home_margin"]
           and whole["available_ram"]-whole["required_ram"]==whole["ram_margin"]
           and not whole["resource_credit_bytes"], "joint 169/170 contract changed")
    c.need(loan==quote.returned_loan() and identity==c.identity(partial.lstat()), "retroactive loan or custody change")
    writer=whole["writer"]
    if not preliminary:
        active=quote.bound(writer)
        ready=quote.bound(active["ready"])
        c.need(ready.get("private169_retry_scope")==ref and ready.get("private169_retry_cadence")==scope["cadence_source"]
               and not active["producer_mutations"], "active cadence did not enroll the epoch 169 retry")
    floor,home,ram=geometry(whole,c.HOME_OUTPUT)
    return dict(schema="horizon-169-hourly-joint-native-price-v1",recorded_unix=time.time(),scope=ref,provider=prov,
                registration=br,writer=writer,predecessor_custody=scope["predecessor"],returned_159_loan=loan,
                whole_roster=whole,stage="native-postguard" if native["independent_retry169"] else "native-prestart",
                candidate_home_already_paid=new169["additional_home"],candidate_ram_already_paid=new169["additional_ram"],
                guard_floor=floor,home_margin=home,ram_margin=ram,fits=home>=0 and ram>=0,
                preliminary=preliminary,resource_credit_bytes=0,canonical_publication_authorized=False)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("prepare-quote","quote","launch"))
    args=cli.parse_args()
    owner=load_owner()
    c=owner["c"]
    c.need(Path(__file__).resolve()==DEPLOY/"joint_issuer.py","use the sealed common-price consumer")
    scope,ref=c.read(ROOT/"SCOPE.json",BASE_SCOPE)
    with owner["quote"].LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=="launch":
            launch=owner["launch"]
            launch.__globals__["funded"]=lambda scope,ref:jointly_funded(owner,scope,ref)
            result=launch()
        else:
            result=jointly_funded(owner,scope,ref,preliminary=args.action=="prepare-quote")
            result=c.recorded(ROOT/f"JOINT_{time.time_ns()}.json",result)
    print(json.dumps(result))
