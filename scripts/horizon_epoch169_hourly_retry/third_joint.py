"""Release the projected 169 worker through the complete 169/170 admission and its enrolled cadence."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time


BASE=Path("/var/lib/jetstreamer/horizon_runtime_data")
ATTEMPT=BASE/"epoch169-hourly-retry-20261128-v3"
OP=ATTEMPT/"operator-v1"
DIR=ATTEMPT/"issuer-v3"
EARLIER_ISSUER="61fe3e066485d9bd64a210dea9c3a4bdd4244635529b7f162ed811a828038844"
OLDER=BASE/"epoch169-hourly-retry-20261128-v2/issuer-v1"
SCOPES=BASE/"epoch162-first-hourly-completion-20261127-v2"
SCOPE="7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
OPERATOR="9203f263c94be2d6ae9cacbcda15b72cfed8662146b940af1704cd617e582196"
STOP="c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02"
FIRST="f3b52be3ead4604505e854bd20c9fc1ec36d278c6f1fc15fc6eb54b3e78ea4ac"
PARENT="c92dcb9d238e1aff668adfcd5c4bb479bbe1d1458868058ac040326e81149788"
THIRD_PEER="66f24b837f2168ff4474ab07def6d50470527334dd91e7570502c424b9da0283"
G=1<<30


def load():
    module=OLDER/"second_joint.py"
    if hashlib.sha256(module.read_bytes()).hexdigest()!=PARENT:
        raise ValueError("different measured admission geometry")
    template=runpy.run_path(str(module))
    template["load"].__globals__.update(OP=OP,OP_SHA=OPERATOR)
    return template["load"](),template["geometry"]


def install(owner, provider, digest, revision, observed):
    c,q=owner["c"],owner["quote"]
    _,scope=c.read(ATTEMPT/"SCOPE.json",SCOPE)
    qualification=q.verified_provider(provider,digest)
    earlier=ATTEMPT/"issuer-v2"
    previous,receipt=c.read(earlier/"deployment-seal-receipt.json",EARLIER_ISSUER)
    native_sources={m["name"]:m["sha256"] for m in previous["members"]}
    old,_=c.read(earlier/"SOURCE.json",native_sources["SOURCE.json"])
    c.need(previous["destination"]==str(earlier) and old["scope"]==scope and
           old["common_provider"]!=qualification and
           not any(os.path.lexists(ATTEMPT/name) for name in ("HELD_GATE.json","GUARD_PLAN.json","START_INTENT.json","GRANT.json")),
           "third 169 is already issued or the provider did not change")
    c.need(provider.parent==SCOPES and provider.name.startswith("issued-price-v") and
           (provider/"retry169_peer.py").is_file() and hashlib.sha256((provider/"retry169_peer.py").read_bytes()).hexdigest()==THIRD_PEER,
           "different common provider or 169 observer")
    src=Path(__file__).resolve()
    prefix="scripts/horizon_epoch169_hourly_retry/"
    body=subprocess.check_output(["git","show",revision+":"+prefix+src.name],cwd=src.parent)
    c.need(src.read_bytes()==body and subprocess.run(["git","merge-base","--is-ancestor",revision,observed],cwd=src.parent).returncode==0
           and not os.path.lexists(DIR), "issuer source, review or destination changed")
    stage=Path(tempfile.mkdtemp(prefix="third-joint-source.",dir=ATTEMPT))
    report=c.stable(OLDER/"first_progress.py",expected=FIRST,sealed=True,keep_bytes=True)[1]
    (stage/src.name).write_bytes(body)
    (stage/"first_progress.py").write_bytes(report)
    _,stop=c.read(ATTEMPT.parent/"epoch169-hourly-retry-20261128-v2/WORKER_ALIAS_STOP.json",STOP)
    c.recorded(stage/"SOURCE.json",dict(schema="horizon-169-third-joint-registration-v1",scope=scope,operator=OPERATOR,
        second_guard_stop=stop,common_provider=qualification,previous_issuer=receipt,previous_provider=old["common_provider"],
        third_peer_sha256=THIRD_PEER,source_commit=revision,
        remote_observed=observed,remote_contains_commit=True,producer_mutations=False,canonical_publication_authorized=False))
    members=[dict(name=p.name,source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),mode=0o444) for p in sorted(stage.iterdir())]
    ref=c.recorded(ATTEMPT/f"ISSUER_PLAN_{time.time_ns()}.json",dict(schema="jetstreamer-sealed-deployment-plan-v1",
        destination=str(DIR),members=members))
    sealer=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
    sha="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
    c.stable(sealer,expected=sha,sealed=True)
    subprocess.run([str(sealer),ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",sha],check=True)
    installed,binding=c.read(DIR/"deployment-seal-receipt.json")
    c.need(installed["plan_sha256"]==ref["sha256"] and installed["destination"]==str(DIR),"different installed issuer")
    return binding


def price(owner,geometry,scope,sr,preliminary=False):
    c,q=owner["c"],owner["quote"]
    r,br=c.read(DIR/"SOURCE.json")
    p=Path(r["common_provider"]["path"]).parent
    provider=q.verified_provider(p,r["common_provider"]["sha256"])
    c.need(r["scope"]==sr==dict(path=str(ATTEMPT/"SCOPE.json"),sha256=SCOPE) and r["common_provider"]==provider
           and p.parent==SCOPES and r["operator"]==scope["operator"]["sha256"]==OPERATOR
           and r["second_guard_stop"]==scope["second_guard_stop"] and r["third_peer_sha256"]==THIRD_PEER,
           "different third 169 or shared provider")
    prior=q.bound(scope["predecessor"])["retained_incomplete_archive"]
    path=Path(prior["path"])
    saved=c.identity(path.lstat())
    c.need(all(prior[k]==v for k,v in saved.items()),"old partial changed")
    loan=q.returned_loan()
    whole=runpy.run_path(str(p/"capacity.py"))["whole_roster"]()
    native=whole["base_169"]["native"]
    booked=native["planned_169_retry"]
    other=native["ram_gap170"]
    candidate=native["independent_retry169"]
    actors=whole["base_169"]["observed_actors"]
    def rows(epoch,actor):
        return [] if not actor else [dict(epoch=epoch,unit=actor["unit"],invocation_id=actor["invocation"])]
    c.need(whole["package"]==provider and booked["third_scope"]==sr and booked["second_guard_stop"]==scope["second_guard_stop"]
           and booked["additional_home"]==c.HOME_OUTPUT+c.CONTROL_BYTES and booked["additional_ram"]==8*G
           and native["stopped_169_compute_handoff"]["retained_159_ram"]+booked["additional_ram"]==c.RAM
           and booked["original_169_guard_retained"] and booked["original_170_guard_cpu_retained"]
           and native["independent_gap_funding"]["cpu_donor"]==loan["scope"] and not whole["resource_credit_bytes"]
           and (not candidate or candidate["unit"]==c.UNIT) and [r for r in actors if r["epoch"]==169]==rows(169,candidate)
           and [r for r in actors if r["epoch"]==170]==rows(170,other)
           and (not other or other["phase"] in ("held","bootstrap","worker"))
           and q.returned_loan()==loan and c.identity(path.lstat())==saved,"inconsistent pair or resource lineage")
    if not preliminary:
        current=owner["read_active_writer"](c,whole["writer"])
        ready=q.bound(current["ready"])
        c.need(ready.get("private169_retry3_scope")==sr and ready.get("private169_retry3_cadence")==scope["cadence_source"]
               and not current["producer_mutations"],"current writer has not enrolled this third scope")
    floor,margin=geometry(whole,(other["floor"] or 0) if other else 0,c.HOME_OUTPUT)
    return dict(schema="horizon-169-projected-worker-joint-price-v1",scope=sr,recorded_unix=time.time(),provider=provider,
        registration=br,writer=whole["writer"],returned_159_loan=loan,predecessor_custody=scope["predecessor"],
        second_guard_stop=scope["second_guard_stop"],whole_roster=whole,
        stage="native-postguard" if candidate else "native-prestart",guard_floor=floor,home_margin=margin,
        ram_margin=whole["ram_margin"],fits=bool(whole["fits"] and min(margin,whole["ram_margin"])>=0),
        preliminary=preliminary,resource_credit_bytes=0,canonical_publication_authorized=False)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("install","prepare-quote","quote","launch","first-progress"))
    cli.add_argument("--provider",type=Path)
    cli.add_argument("--provider-sha")
    cli.add_argument("--commit")
    cli.add_argument("--observed")
    opts=cli.parse_args()
    owner,geometry=load()
    c=owner["c"]
    if opts.action=="install":
        result=install(owner,opts.provider,opts.provider_sha,opts.commit,opts.observed)
    else:
        c.need(Path(__file__).resolve()==DIR/"third_joint.py","use the issued third gate")
        scope,sr=c.read(ATTEMPT/"SCOPE.json",SCOPE)
        if opts.action=="first-progress":
            result=runpy.run_path(str(DIR/"first_progress.py"))["follow"](owner,scope,sr)
        else:
            with owner["quote"].LOCK.open("rb") as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                if opts.action=="launch":
                    start=owner["launch"]
                    start.__globals__["funded"]=lambda s,r:price(owner,geometry,s,r)
                    result=start()
                else:
                    fresh=price(owner,geometry,scope,sr,preliminary=opts.action=="prepare-quote")
                    result=c.recorded(ATTEMPT/f"JOINT_{time.time_ns()}.json",fresh)
    print(json.dumps(result))
