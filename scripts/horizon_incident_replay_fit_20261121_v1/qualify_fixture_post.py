"""Verify the V7 release boundary before publishing a registered V21 price."""
from copy import deepcopy
from pathlib import Path
import json
import runpy
import sys
from unittest.mock import Mock, patch


def verify(provider):
    module = runpy.run_path(str(provider))
    s = module["s"]
    root = module["R"]
    release_route = module["released136_route"]
    verify_release = module["validate_v7_release"]
    scope = verify_release.__globals__
    pkg = module["D"] / "tools-v21"
    current = root / "epoch145-fixture-phase-dispatch-20261122-v1"
    retired = root / "epoch145-phase-dispatch-20261122-v1"
    controller = root / "epoch136-joint-writer-20261122-v7/controller"
    v5f = root / "epoch145-semantic-continuity-20261121-v1"
    profile, _ = s.read(provider.parent / "profile136-fixture-writer.json")
    seal, sr = s.read(controller / "deployment-seal-receipt.json", profile["seal_sha256"])
    s.need(seal["destination"]==str(controller) and any(m["name"]=="admit136" and
           m["sha256"]==profile["image_sha256"] and m["mode"]=="0555" for m in seal["members"]),
           "foreign V7 writer package")
    module["fit"].binary(controller / "admit136", profile["image_sha256"])
    cfg,adapter,post=module["profile145"](provider.parent,focused="fixture-post")
    worker,wr=s.read(v5f / "V5F_ACTUAL_ADVANCING_WORKER.json")
    q = s.bound(worker["start"],root/"epoch145-guarded-export-20261121-v1/state"/worker["invocation_id"]/"recovery-started.json")
    target=q["prior_frozen_recovery"]["failed_qualification_census"]["current_boot_failure"]["failure"]
    s.need(target==s.ref(root/"epoch145-guarded-export-20261121-v1/state/a99ed8b51e8a482b805b8a36a11b2700/failed.json",
                         "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"),"foreign V5f predecessor")
    image_hash = __import__("hashlib").sha256(provider.read_bytes()).hexdigest()
    # READY, OFFER and release belong to the later real registrar; use offline rows only here.
    v21_seal=s.ref(pkg/"deployment-seal-receipt.json","f"*64)
    v21_image=s.ref(pkg/"post-stop-fit",image_hash)
    selector=s.ref(current/"READY.json","a"*64)
    select=dict(original_semantic_invocation=worker["invocation_id"],
                registered_provider=dict(image=v21_image,seal=v21_seal),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    plan_ref=s.ref(controller.parent/"registered-production-plan.json","c"*64)
    plan=dict(holding145_semantic_worker=wr,holding145_prestart_ready=selector,
              holding145_completion=dict(seal=post["seal"],build=post["build"],adapter=s.ref(adapter,cfg["adapter_sha256"])))
    released=dict(schema="horizon-136-incident-donor-released-v1",boot_id=select["boot_id"],writer_invocation_id="d"*32)
    reader=Mock(wraps=s);fit=Mock(wraps=module["fit"])
    def read(path,*args):
        if path==pkg/"profile136-fixture-writer.json":return profile,{}
        if path==pkg/"deployment-seal-receipt.json":
            return dict(destination=str(pkg),members=[dict(name="post-stop-fit",sha256=image_hash)]),v21_seal
        return s.read(path,*args)
    def bound(ref,path):
        if path==current/"READY.json":
            s.need(ref==selector,"foreign synthetic selector")
            return ready
        return s.bound(ref,path)
    def binary(path,digest):
        if path==pkg/"post-stop-fit":
            s.need(digest==image_hash,"foreign native V21 digest")
        else:module["fit"].binary(path,digest)
    reader.read.side_effect=read;reader.bound.side_effect=bound;fit.binary.side_effect=binary
    scenarios = ("positive","V2 READY","foreign READY","V5e semantic generation","V12 completion","V6 writer plan",
                 "wrong V21 seal","wrong V21 image","unrelated donor boot","foreign release writer")
    with patch.dict(scope, __file__=str(pkg/"post-stop-fit"),s=reader,fit=fit,
                    profile145=lambda *a,**k:(cfg,adapter,post)):
        for case in scenarios:
            chosen=selector.copy();ready=deepcopy(select);actual=deepcopy(plan);pr=plan_ref.copy();done=released.copy()
            if case=="V2 READY":chosen["path"]=str(retired/"READY.json")
            if case=="foreign READY":chosen["path"]=str(current/"FORGED.json")
            if case=="V5e semantic generation":ready["original_semantic_invocation"]="a99ed8b51e8a482b805b8a36a11b2700"
            if case=="V12 completion":actual["holding145_completion"]["seal"]["path"]=str(v5f/"tools-v12/deployment-seal-receipt.json")
            if case=="V6 writer plan":pr["path"]=str(root/"epoch136-joint-writer-20261122-v6/registered-production-plan.json")
            if case=="wrong V21 seal":ready["registered_provider"]["seal"]["sha256"]="0"*64
            if case=="wrong V21 image":ready["registered_provider"]["image"]["sha256"]="0"*64
            if case=="unrelated donor boot":done["boot_id"]="foreign"
            if case=="foreign release writer":done["writer_invocation_id"]="0"*32
            try:
                dispatch,ctrl,wprofile=release_route({"selector":chosen})
                s.need((dispatch,ctrl,wprofile)==(current,controller,profile),"foreign 136 release package")
                verify_release(dispatch,ctrl,chosen,pr,actual,done)
            except ValueError:
                if case=="positive":raise
            else:s.need(case=="positive","accepted crossed "+case)
    return dict(v7_controller=sr,v13=post,v5f_worker=wr,checks=list(scenarios),
                production_selector_created=False,donor_or_candidate_started=False)


if __name__=="__main__":
    print(json.dumps(verify(Path(sys.argv[1])),sort_keys=True))
